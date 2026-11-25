// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Package ingest turns what infraharvest's pkg/tfstate reads from Terraform
// state into the rows of a snapshot: a node for each resource instance, data
// source, module call and state, and the edges between them. It keeps what
// pkg/tfstate keeps, which is the address, the type and the ID or ARN of an
// instance, and the places a state reads other states from, and writes
// nothing else: no attribute value, no output value, no tag.
package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/IgnatG/infraharvest/pkg/tfstate"
	"github.com/IgnatG/infraharvest/pkg/typemap"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// Edge bases written by the state reader.
const (
	BasisStateDependency   = "state_dependency"
	BasisModuleContainment = "module_containment"
	BasisStateMembership   = "state_membership"
	BasisRemoteState       = "remote_state"
)

// Read is what one location the user named held: the states in it, or why
// they could not be read.
type Read struct {
	// Location is the location as pkg/tfstate reads it (see Resolve).
	Location string
	Docs     []tfstate.Document
	Err      error
}

// ReadAll reads each location in order. A location that fails is recorded
// and does not stop the rest, so that one state out of reach gives a partial
// snapshot and not none.
func ReadAll(ctx context.Context, locations []string, stores tfstate.Stores) []Read {
	reads := make([]Read, 0, len(locations))
	for _, loc := range locations {
		r := Read{Location: loc}
		r.Docs, r.Err = tfstate.Read(ctx, loc, stores)
		reads = append(reads, r)
	}
	return reads
}

// Options say who reads and when.
type Options struct {
	// CollectedAt is when the states were read. The writer does not read
	// the clock.
	CollectedAt time.Time
	// Collector and CollectorVersion name the program.
	Collector, CollectorVersion string
}

// Result is the rows of the states, and what they cannot tell you.
type Result struct {
	Tables snapshot.Tables
	// Limits is plain text for the manifest.
	Limits string
	// Failed is how many locations did not read.
	Failed int
}

// Build turns what was read into rows. It fails only if no state was read at
// all; a location that failed is a source with status failed.
func Build(reads []Read, o Options) (Result, error) {
	tm, err := typemap.New()
	if err != nil {
		return Result{}, err
	}
	b := &builder{
		tm: tm, o: o,
		nodes: map[string]snapshot.Node{}, edges: map[edgeKey]snapshot.Edge{},
		producers: map[string][]*docState{}, externals: map[string]bool{},
	}
	var docs []tfstate.Document
	for _, r := range reads {
		if r.Err != nil {
			b.fail(r)
			continue
		}
		docs = append(docs, r.Docs...)
	}
	if len(docs) == 0 {
		return Result{}, fmt.Errorf("no state could be read:%s", b.failureList())
	}
	sort.SliceStable(docs, func(i, j int) bool { return Sanitise(docs[i].Source) < Sanitise(docs[j].Source) })
	var states []*docState
	for _, d := range docs {
		s := b.addDocument(d)
		states = append(states, s)
		if k := producerKey(d.Source); k != "" {
			b.producers[k] = append(b.producers[k], s)
		}
	}
	for _, s := range states {
		b.addEdges(s)
	}
	return Result{Tables: b.tables(), Limits: b.limits(), Failed: len(b.failed)}, nil
}

type edgeKey struct{ kind, from, to string }

// docState is a state being turned into rows.
type docState struct {
	doc    tfstate.Document
	loc    string
	source string
	root   string
	// byAddress maps an instance's address, and byKeyless the address
	// without its instance keys, to the nodes of the instances at it.
	byAddress, byKeyless map[string][]string
	// calls maps the keyless address of a module call to its nodes.
	calls map[string][]string
	// members are the nodes of the instances, in the order of the state.
	members []member
}

type member struct {
	node snapshot.Node
	call string // the innermost module call's full address
}

type builder struct {
	tm        *typemap.Resolver
	o         Options
	sources   []snapshot.Source
	nodes     map[string]snapshot.Node
	edges     map[edgeKey]snapshot.Edge
	producers map[string][]*docState
	failed    []Read
	externals map[string]bool

	duplicates, noID, unresolved, unplaced int
}

func (b *builder) fail(r Read) {
	b.failed = append(b.failed, r)
	loc := Sanitise(r.Location)
	b.sources = append(b.sources, snapshot.Source{
		SourceID: sourceID(loc), Kind: snapshot.SourceState, Backend: BackendOf(r.Location),
		Location: loc, CollectedAt: b.at(), Collector: b.o.Collector, CollectorVersion: b.o.CollectorVersion,
		Status: snapshot.StatusFailed, Reason: Scrub(r.Err.Error()),
	})
}

func (b *builder) failureList() string {
	var sb strings.Builder
	for _, r := range b.failed {
		sb.WriteString("\n  " + Scrub(r.Err.Error()))
	}
	return sb.String()
}

func (b *builder) at() string { return b.o.CollectedAt.UTC().Format(time.RFC3339) }

func sourceID(location string) string {
	sum := sha256.Sum256([]byte(location))
	return "state-" + hex.EncodeToString(sum[:])[:12]
}

func (b *builder) addNode(n snapshot.Node) {
	if _, ok := b.nodes[n.NodeID]; ok {
		if n.Kind == snapshot.KindResource && n.Address != "" {
			b.duplicates++
		}
		return
	}
	b.nodes[n.NodeID] = n
}

func (b *builder) addEdge(kind, basis, conf, from, to, source string) {
	if from == to {
		return
	}
	k := edgeKey{kind, from, to}
	if old, ok := b.edges[k]; ok && rank(old.Confidence) >= rank(conf) {
		return
	}
	b.edges[k] = snapshot.Edge{
		EdgeID: snapshot.EdgeID(kind, from, to), FromID: from, ToID: to,
		Kind: kind, Confidence: conf, Basis: basis, SourceID: source,
	}
}

// rank orders confidences: observed is the strongest.
func rank(c string) int {
	switch c {
	case snapshot.Observed:
		return 3
	case snapshot.Computed:
		return 2
	}
	return 1
}

// addDocument adds the source, the state root and a node for each instance
// and module call of d.
func (b *builder) addDocument(d tfstate.Document) *docState {
	loc := Sanitise(d.Source)
	s := &docState{
		doc: d, loc: loc, source: sourceID(loc),
		byAddress: map[string][]string{}, byKeyless: map[string][]string{}, calls: map[string][]string{},
	}
	src := snapshot.Source{
		SourceID: s.source, Kind: snapshot.SourceState, Backend: BackendOf(d.Source), Location: loc,
		Workspace: WorkspaceOf(d.Source), Lineage: d.Lineage, TerraformVersion: d.TerraformVersion,
		DocumentSHA256: digest(d), CollectedAt: b.at(),
		Collector: b.o.Collector, CollectorVersion: b.o.CollectorVersion, Status: snapshot.StatusOK,
	}
	if d.Serial > 0 || d.Lineage != "" {
		serial := d.Serial
		src.Serial = &serial
	}
	b.sources = append(b.sources, src)

	s.root = snapshot.NodeID(snapshot.KindStateRoot, "", "", "", "", loc)
	b.addNode(snapshot.Node{
		NodeID: s.root, Kind: snapshot.KindStateRoot, NativeID: loc, Name: rootName(loc), Root: loc,
		ManagedStatus: snapshot.Managed, Confidence: snapshot.Observed, SourceID: s.source,
	})

	for _, in := range d.Instances {
		n := b.instanceNode(s, in)
		b.addNode(n)
		s.byAddress[in.Address] = append(s.byAddress[in.Address], n.NodeID)
		k := keyless(in.Address)
		s.byKeyless[k] = append(s.byKeyless[k], n.NodeID)
		calls := moduleCalls(in.Module)
		m := member{node: n}
		if len(calls) > 0 {
			m.call = calls[len(calls)-1]
		}
		s.members = append(s.members, m)
		for _, call := range calls {
			id := snapshot.NodeID(snapshot.KindModuleCall, "", "", "", "", loc+"|"+call)
			if _, ok := b.nodes[id]; !ok {
				b.nodes[id] = snapshot.Node{
					NodeID: id, Kind: snapshot.KindModuleCall, NativeID: loc + "|" + call, Name: callName(call),
					Address: call, Module: parentCall(call), Root: loc, ManagedStatus: snapshot.Managed,
					Confidence: snapshot.Observed, SourceID: s.source,
				}
			}
			if !slices.Contains(s.calls[keyless(call)], id) {
				s.calls[keyless(call)] = append(s.calls[keyless(call)], id)
			}
		}
	}
	return s
}

// parentCall is the module path a module call is in.
func parentCall(call string) string {
	parts := splitTop(call)
	if len(parts) <= 2 {
		return ""
	}
	return strings.Join(parts[:len(parts)-2], ".")
}

func rootName(loc string) string {
	if i := strings.LastIndex(strings.TrimRight(loc, "/"), "/"); i >= 0 {
		return strings.TrimRight(loc, "/")[i+1:]
	}
	return loc
}

// instanceNode is the node of one resource instance or data source.
func (b *builder) instanceNode(s *docState, in tfstate.Instance) snapshot.Node {
	cloud := cloudOf(in.Provider, in.Type)
	id, arn := in.ID, in.ARN
	switch {
	case isGenerated(in):
		id, arn = "", ""
	case Scrub(id) != id || Scrub(arn) != arn:
		// An ID that is, or holds, a credential (a token, or a URL with a
		// user, a password or a query string) is never written down.
		id, arn = "", ""
		b.noID++
	}
	sc := scopeOf(cloud, id, arn, in.IdentityID)
	tfType := b.tm.Canonical(in.Type)

	managed := snapshot.Managed
	// The thing a data source reads is not necessarily managed by this
	// state, and the same thing can be read by many: a data source is
	// identified by where it is.
	key := sc.id
	if in.Mode == "data" {
		managed = snapshot.Unknown
		key = "data:" + s.loc + "|" + in.Address
	} else if key == "" {
		key = "tf:" + s.loc + "|" + in.Address
	}
	return snapshot.Node{
		NodeID: snapshot.NodeID(snapshot.KindResource, cloud, sc.account, sc.region, tfType, key),
		Kind:   snapshot.KindResource, Cloud: cloud, Account: sc.account, Region: sc.region,
		TFType: tfType, NativeID: sc.id, ARNOrPath: sc.path, Name: in.Name,
		Address: in.Address, Module: in.Module, Root: s.loc,
		ManagedStatus: managed, Confidence: snapshot.Observed, SourceID: s.source,
	}
}

// isGenerated reports whether an instance's ID is a value Terraform makes up
// and may be used as a secret (random_string's id is its result), and not an
// identifier of a thing in a cloud.
// Providers whose IDs are free text are left out too: http (the URL it read),
// external (whatever the program printed), local, null, time, archive and tls.
func isGenerated(in tfstate.Instance) bool {
	if in.Mode == "data" && in.Type == "terraform_remote_state" {
		return true
	}
	return freeTextProviders[providerName(in.Provider)] || strings.HasPrefix(in.Type, "random_")
}

func providerName(provider string) string {
	i := strings.LastIndex(provider, "/")
	if i < 0 {
		return ""
	}
	return strings.Trim(provider[i+1:], `"]`)
}

// addEdges adds the edges of one state.
func (b *builder) addEdges(s *docState) {
	for _, m := range s.members {
		b.addEdge(snapshot.EdgeDefinedIn, BasisStateMembership, snapshot.Observed, m.node.NodeID, s.root, s.source)
	}
	for _, in := range s.doc.Instances {
		for _, id := range s.byAddress[in.Address] {
			b.dependencies(s, id, in)
		}
	}
	// Module containment: a call is in the call around it, or in the state.
	// Walk every call of the state once.
	seen := map[string]bool{}
	for _, m := range s.members {
		calls := moduleCalls(m.node.Module)
		if len(calls) > 0 {
			b.addEdge(snapshot.EdgeContainedIn, BasisModuleContainment, snapshot.Computed,
				m.node.NodeID, b.callID(s, calls[len(calls)-1]), s.source)
		}
		for i, call := range calls {
			if seen[call] {
				continue
			}
			seen[call] = true
			to := s.root
			if i > 0 {
				to = b.callID(s, calls[i-1])
			}
			b.addEdge(snapshot.EdgeContainedIn, BasisModuleContainment, snapshot.Computed,
				b.callID(s, call), to, s.source)
		}
	}
	b.remoteStates(s)
}

func (b *builder) callID(s *docState, call string) string {
	return snapshot.NodeID(snapshot.KindModuleCall, "", "", "", "", s.loc+"|"+call)
}

// dependencies adds an edge from an instance to each instance, data source or
// module the state says it depends on.
func (b *builder) dependencies(s *docState, from string, in tfstate.Instance) {
	for _, dep := range in.Dependencies {
		to := slices.Concat(s.byKeyless[keyless(dep)], s.calls[keyless(dep)])
		if len(to) == 0 {
			b.unresolved++
			continue
		}
		for _, id := range to {
			b.addEdge(snapshot.EdgeDependsOn, BasisStateDependency, snapshot.Observed, from, id, s.source)
		}
	}
}

// remoteStates adds an edge from each terraform_remote_state data source to
// the state it reads, or to a placeholder when that state is not in the
// snapshot.
func (b *builder) remoteStates(s *docState) {
	for _, rs := range s.doc.RemoteStates {
		from := s.root
		if ids := s.byAddress[rs.Address]; len(ids) > 0 {
			from = ids[0]
		}
		found := false
		for _, want := range consumerKeys(rs) {
			for key, producers := range b.producers {
				if !matches(key, want) {
					continue
				}
				for _, p := range producers {
					if p != s {
						b.addEdge(snapshot.EdgeReadsStateOf, BasisRemoteState, snapshot.Observed, from, p.root, s.source)
						found = true
					}
				}
			}
		}
		if found {
			continue
		}
		loc, ok := remoteLocation(rs)
		native := loc
		if !ok {
			// The settings name no state this reader can place.
			b.unplaced++
			native = "unplaced:" + s.loc + "#" + rs.Address
			loc = "(unplaced) " + rs.Backend + " backend of " + rs.Address
		} else {
			b.externals[loc] = true
		}
		id := snapshot.NodeID(snapshot.KindExternal, "", "", "", "", native)
		b.addNode(snapshot.Node{
			NodeID: id, Kind: snapshot.KindExternal, NativeID: native, Name: loc,
			ManagedStatus: snapshot.Unknown, Confidence: snapshot.Inferred, SourceID: s.source,
		})
		b.addEdge(snapshot.EdgeReadsStateOf, BasisRemoteState, snapshot.Observed, from, id, s.source)
	}
}

// tables returns the rows.
func (b *builder) tables() snapshot.Tables {
	t := snapshot.Tables{Sources: b.sources}
	for _, n := range b.nodes {
		t.Nodes = append(t.Nodes, n)
	}
	for _, e := range b.edges {
		t.Edges = append(t.Edges, e)
	}
	return t
}

// limits is what the snapshot cannot tell you, in plain text.
func (b *builder) limits() string {
	var s []string
	s = append(s, "Read from Terraform state only: no live inventory was read, so nothing is marked unmanaged.",
		"Attribute values, output values and tags are never read: the only values kept from a resource are its id and ARN.")
	if len(b.externals) > 0 {
		var locs []string
		for l := range b.externals {
			locs = append(locs, l)
		}
		sort.Strings(locs)
		more := ""
		if len(locs) > 10 {
			more, locs = fmt.Sprintf(" and %d more", len(locs)-10), locs[:10]
		}
		s = append(s, fmt.Sprintf("%d states read by terraform_remote_state are not in this snapshot, so anything that depends on them stops at an external placeholder: %s%s.",
			len(b.externals), strings.Join(locs, ", "), more))
	}
	if b.unplaced > 0 {
		s = append(s, strconv.Itoa(b.unplaced)+" terraform_remote_state data sources use a backend whose settings name no state this reader can place, so they point to a placeholder.")
	}
	if b.unresolved > 0 {
		s = append(s, strconv.Itoa(b.unresolved)+" dependencies name an address the state does not hold and are left out.")
	}
	if b.duplicates > 0 {
		s = append(s, strconv.Itoa(b.duplicates)+" resources are held by more than one state and are listed once, under the first state read.")
	}
	if b.noID > 0 {
		s = append(s, strconv.Itoa(b.noID)+" instances have an id or ARN that looks like a credential and are identified by their address instead.")
	}
	return strings.Join(s, " ")
}

// digest is the SHA-256 of what is kept of a state: its serial, lineage and
// version, and the address, type, id and dependencies of each instance. It is
// not the hash of the state's bytes, which are not kept, but changes whenever
// anything this reader keeps changes.
func digest(d tfstate.Document) string {
	h := sha256.New()
	w := func(fields ...string) {
		for _, f := range fields {
			h.Write([]byte(f))
			h.Write([]byte{0})
		}
		h.Write([]byte{'\n'})
	}
	w(strconv.FormatInt(d.Serial, 10), d.Lineage, d.TerraformVersion)
	for _, in := range d.Instances {
		w(append([]string{in.Mode, in.Address, in.Provider, in.ID, in.ARN, in.IdentityID}, in.Dependencies...)...)
	}
	for _, o := range d.Outputs {
		w("output", o.Name, strconv.FormatBool(o.Sensitive))
	}
	for _, r := range d.RemoteStates {
		w("remote", r.Address, r.Backend, r.Account, r.Bucket, r.Key, r.Host, r.Organization, r.Workspace)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// freeTextProviders are the providers whose IDs are made up by Terraform or
// are free text, never the identifier of a thing in a cloud.
var freeTextProviders = map[string]bool{
	"random": true, "http": true, "external": true, "local": true,
	"null": true, "time": true, "archive": true, "tls": true,
}
