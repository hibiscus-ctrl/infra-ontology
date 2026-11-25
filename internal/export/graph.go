// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Package export writes a snapshot as a document another tool reads. Today
// that is infraharvest's graph/v1, which Terragram's renderer draws. The
// export is lossy by design and never writes more than the snapshot says it
// may: hashed addresses stay hashed, dropped ones stay dropped.
package export

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// GraphSchema is the value of the schema member of a graph/v1 document.
const GraphSchema = "infraharvest/graph/v1"

// The kinds of a graph/v1 node.
const (
	nodeResource = "resource"
	nodeModule   = "module"
)

// graph/v1 names a module call by its registry source. A snapshot does not
// keep a module's source, so every module call is "other", which graph/v1
// also uses for a source it will not share.
const moduleSource = "other"

// What redaction.addresses says of the addresses.
const (
	addressesPlain   = "plain"
	addressesHashed  = "hashed"
	addressesDropped = "dropped"
)

const (
	hashAlgorithm = "hmac-sha256"
	unknownScope  = "unknown"
)

// Options are what an export may be told.
type Options struct {
	// Cloud is the cloud to export: aws, azure or google (gcp is accepted).
	// A graph/v1 document has one cloud, so a snapshot of several needs it.
	Cloud string
	// Tool is the program that writes the document.
	Tool snapshot.Tool
}

// Node is a node of a graph/v1 document: an imported resource, or a module
// call. Parent is the index of the module call a resource is in.
type Node struct {
	Kind          string `json:"kind"`
	Type          string `json:"type,omitempty"`
	ID            string `json:"id,omitempty"`
	Account       string `json:"account"`
	Region        string `json:"region,omitempty"`
	Environment   string `json:"environment,omitempty"`
	Address       string `json:"address,omitempty"`
	Root          string `json:"root,omitempty"`
	ModuleAddress string `json:"module_address,omitempty"`
	Source        string `json:"source,omitempty"`
	Version       string `json:"version,omitempty"`
	Parent        *int   `json:"parent,omitempty"`
}

// Edge says the node From refers to the node To.
type Edge struct {
	From int `json:"from"`
	To   int `json:"to"`
}

// Redaction says what was done to the ids and to the addresses.
type Redaction struct {
	IDsHashed bool   `json:"ids_hashed"`
	HashAlg   string `json:"hash_alg"`
	Addresses string `json:"addresses"`
}

// Graph is a graph/v1 document (infraharvest/graph/v1).
type Graph struct {
	Schema      string        `json:"schema"`
	RunID       string        `json:"run_id"`
	GeneratedAt string        `json:"generated_at"`
	Tool        snapshot.Tool `json:"tool"`
	Cloud       string        `json:"cloud"`
	Nodes       []Node        `json:"nodes"`
	Edges       []Edge        `json:"edges"`
	Redaction   Redaction     `json:"redaction"`
}

// Dropped counts what graph/v1 could not hold, by the reason it was left out.
type Dropped struct {
	// Nodes counts snapshot nodes left out, by their kind (state_root,
	// account, external), or by why a resource or module call was (other_cloud,
	// no_cloud, no_type_or_id).
	Nodes map[string]int `json:"nodes"`
	// Edges counts snapshot edges that are not a reference between two nodes
	// of the document, by their kind. A containment edge that became a node's
	// parent is not counted.
	Edges map[string]int `json:"edges"`
}

// Total is the number of nodes and edges left out.
func (d Dropped) Total() (nodes, edges int) {
	for _, n := range d.Nodes {
		nodes += n
	}
	for _, n := range d.Edges {
		edges += n
	}
	return nodes, edges
}

// String lists what was dropped, in a fixed order, for example
// "nodes: account 2, state_root 2; edges: defined_in 2".
func (d Dropped) String() string {
	list := func(m map[string]int) string {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
		}
		if len(parts) == 0 {
			return "none"
		}
		return strings.Join(parts, ", ")
	}
	return "nodes: " + list(d.Nodes) + "; edges: " + list(d.Edges)
}

// Result is a graph and what it lost.
type Result struct {
	Graph   *Graph
	Dropped Dropped
}

// ToGraph maps a verified snapshot to a graph/v1 document.
//
// A resource becomes a resource node, a module call a module node, and a
// depends_on edge between two of them a reference. A resource's parent is the
// module call a contained_in edge puts it in. Everything else is left out and
// counted: state roots, accounts, placeholders, tags, names, ARNs, the other
// edge kinds and the other clouds.
func ToGraph(l *snapshot.Loaded, opts Options) (*Result, error) {
	if l == nil {
		return nil, errors.New("no snapshot")
	}
	b, err := newBuilder(l, opts)
	if err != nil {
		return nil, err
	}
	if err := b.resources(); err != nil {
		return nil, err
	}
	if err := b.modules(); err != nil {
		return nil, err
	}
	b.others()
	b.order()
	b.edges()
	return &Result{Graph: b.graph, Dropped: b.dropped}, nil
}

// Marshal writes a graph as JSON, indented, with a closing newline. The same
// graph gives the same bytes.
func Marshal(g *Graph) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// item is a node of the document on its way to its place in it.
type item struct {
	id   string // the snapshot node_id
	node Node
}

type builder struct {
	l         *snapshot.Loaded
	graph     *Graph
	dropped   Dropped
	cloud     string
	addresses string
	hashed    bool

	byID      map[string]snapshot.Node
	items     []item
	index     map[string]int      // snapshot node_id to index in graph.Nodes
	members   map[string][]string // module call node_id to the resources contained in it
	exported  map[string]bool     // resource node_ids in the document
	rootCount map[string]int      // exported resources by root
}

func newBuilder(l *snapshot.Loaded, opts Options) (*builder, error) {
	b := &builder{
		l:         l,
		dropped:   Dropped{Nodes: map[string]int{}, Edges: map[string]int{}},
		byID:      make(map[string]snapshot.Node, len(l.Tables.Nodes)),
		members:   map[string][]string{},
		exported:  map[string]bool{},
		rootCount: map[string]int{},
	}
	for _, n := range l.Tables.Nodes {
		b.byID[n.NodeID] = n
	}
	red := l.Manifest.Redaction
	if red.IDsHashed && red.HashAlgorithm != hashAlgorithm {
		return nil, fmt.Errorf("the snapshot says its ids are hashed with %q, not %s: nothing is written", red.HashAlgorithm, hashAlgorithm)
	}
	b.hashed = red.IDsHashed
	switch {
	case red.AddressesDropped:
		b.addresses = addressesDropped
	case red.IDsHashed:
		b.addresses = addressesHashed
	default:
		b.addresses = addressesPlain
	}
	cloud, err := b.chooseCloud(opts.Cloud)
	if err != nil {
		return nil, err
	}
	created, err := time.Parse(time.RFC3339, l.Manifest.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("created_at: %w", err)
	}
	b.cloud = cloud
	b.graph = &Graph{
		Schema:      GraphSchema,
		RunID:       runID(l.Manifest.SnapshotID, cloud),
		GeneratedAt: created.UTC().Format("2006-01-02T15:04:05Z"),
		Tool:        opts.Tool,
		Cloud:       cloud,
		Nodes:       []Node{},
		Edges:       []Edge{},
		Redaction:   Redaction{IDsHashed: red.IDsHashed, HashAlg: hashAlgorithm, Addresses: b.addresses},
	}
	return b, nil
}

// cloudName is graph/v1's name for a snapshot's cloud, or "" if it has none.
func cloudName(s string) string {
	switch strings.ToLower(s) {
	case "aws":
		return "aws"
	case "azure", "azurerm":
		return "azure"
	case "gcp", "google":
		return "google"
	}
	return ""
}

// chooseCloud settles the document's cloud: the one asked for, or the only
// one the snapshot's resources are in.
func (b *builder) chooseCloud(want string) (string, error) {
	found := map[string]bool{}
	for _, n := range b.l.Tables.Nodes {
		if n.Kind == snapshot.KindResource {
			if c := cloudName(n.Cloud); c != "" {
				found[c] = true
			}
		}
	}
	have := make([]string, 0, len(found))
	for c := range found {
		have = append(have, c)
	}
	slices.Sort(have)
	if want != "" {
		c := cloudName(want)
		if c == "" {
			return "", fmt.Errorf("unknown cloud %q: graph/v1 has aws, azure and google", want)
		}
		if !found[c] {
			return "", fmt.Errorf("the snapshot has no resources in %s (it has %s)", c, listOrNone(have))
		}
		return c, nil
	}
	switch len(have) {
	case 0:
		return "", errors.New("the snapshot has no resources in aws, azure or google, the clouds graph/v1 names")
	case 1:
		return have[0], nil
	}
	return "", fmt.Errorf("the snapshot has resources in %s and a graph/v1 document has one cloud: choose with --cloud", strings.Join(have, " and "))
}

func listOrNone(s []string) string {
	if len(s) == 0 {
		return "none"
	}
	return strings.Join(s, ", ")
}

// runID is a UUID made from the snapshot and the cloud, so the same snapshot
// always gets the same one. It is shaped as a version 5 UUID.
func runID(snapshotID, cloud string) string {
	sum := sha256.Sum256([]byte(GraphSchema + "\x00" + snapshotID + "\x00" + cloud))
	u := sum[:16]
	u[6] = u[6]&0x0f | 0x50
	u[8] = u[8]&0x3f | 0x80
	h := hex.EncodeToString(u)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// isHash says whether s is a hex SHA-256, what a hashed value looks like.
func isHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// address returns what the document says of an address or a root: nothing
// when the snapshot dropped them, and the value as the snapshot has it
// otherwise. A snapshot that says it hashed them must have: one with a plain
// value is refused, as a document would then say "hashed" of a name.
func (b *builder) address(s, what string) (string, error) {
	switch {
	case s == "" || b.addresses == addressesDropped:
		return "", nil
	case b.addresses == addressesHashed && !isHash(s):
		return "", fmt.Errorf("the snapshot says its addresses are hashed, but the %s of a node is not: nothing is written", what)
	}
	return s, nil
}

// resources adds the snapshot's resources.
func (b *builder) resources() error {
	for _, n := range b.l.Tables.Nodes {
		if n.Kind != snapshot.KindResource {
			continue
		}
		switch c := cloudName(n.Cloud); {
		case c == "" && n.Cloud == "":
			b.dropped.Nodes["no_cloud"]++
			continue
		case c != b.cloud:
			b.dropped.Nodes["other_cloud"]++
			continue
		}
		typ := first(n.TFType, n.InventoryType)
		if typ == "" || n.NativeID == "" {
			b.dropped.Nodes["no_type_or_id"]++
			continue
		}
		if b.hashed && !isHash(n.NativeID) {
			return errors.New("the snapshot says its ids are hashed, but the id of a resource is not: nothing is written")
		}
		node := Node{
			Kind:        nodeResource,
			Type:        typ,
			ID:          n.NativeID,
			Account:     first(n.Account, unknownScope),
			Region:      n.Region,
			Environment: n.Environment,
		}
		var err error
		if node.Address, err = b.address(n.Address, "address"); err != nil {
			return err
		}
		if node.Root, err = b.address(n.Root, "root"); err != nil {
			return err
		}
		b.items = append(b.items, item{id: n.NodeID, node: node})
		b.exported[n.NodeID] = true
		b.rootCount[n.Root]++
	}
	// Which module call each resource is in, from its containment edges.
	for _, e := range b.l.Tables.Edges {
		if e.Kind != snapshot.EdgeContainedIn {
			continue
		}
		from, to := b.byID[e.FromID], b.byID[e.ToID]
		if from.Kind == snapshot.KindResource && to.Kind == snapshot.KindModuleCall {
			b.members[e.ToID] = append(b.members[e.ToID], e.FromID)
		}
	}
	return nil
}

// modules adds the snapshot's module calls. A module call has no account or
// cloud of its own in a snapshot, so it takes them from what it contains: it
// is in the document when one of its resources is, or, if it holds none, when
// its state root has resources in it.
func (b *builder) modules() error {
	for _, n := range b.l.Tables.Nodes {
		if n.Kind != snapshot.KindModuleCall {
			continue
		}
		var in []snapshot.Node // the exported resources it holds
		for _, id := range b.members[n.NodeID] {
			if b.exported[id] {
				in = append(in, b.byID[id])
			}
		}
		if why := b.moduleLeftOut(n, len(in)); why != "" {
			b.dropped.Nodes[why]++
			continue
		}
		node := Node{
			Kind:        nodeModule,
			Account:     first(n.Account, commonest(in, func(r snapshot.Node) string { return r.Account }), unknownScope),
			Region:      first(n.Region, unanimous(in, func(r snapshot.Node) string { return r.Region })),
			Environment: first(n.Environment, unanimous(in, func(r snapshot.Node) string { return r.Environment })),
			Source:      moduleSource,
		}
		var err error
		if node.ModuleAddress, err = b.address(n.Address, "address"); err != nil {
			return err
		}
		if node.Root, err = b.address(n.Root, "root"); err != nil {
			return err
		}
		b.items = append(b.items, item{id: n.NodeID, node: node})
	}
	return nil
}

// moduleLeftOut says why a module call is not in the document, or "" if it is.
// inCount is the number of its resources that are.
func (b *builder) moduleLeftOut(n snapshot.Node, inCount int) string {
	switch {
	case n.Cloud != "" && cloudName(n.Cloud) != b.cloud:
		return "other_cloud"
	case inCount > 0 || n.Cloud != "":
		return ""
	case len(b.members[n.NodeID]) > 0:
		return "other_cloud" // all its resources are in another cloud, or have no type or id
	case n.Root != "" && b.rootCount[n.Root] > 0:
		return "" // holds no resource of its own (it may hold only module calls), in a root that has some
	}
	return "no_cloud"
}

// others counts the nodes that are neither resources nor module calls.
func (b *builder) others() {
	for _, n := range b.l.Tables.Nodes {
		if n.Kind != snapshot.KindResource && n.Kind != snapshot.KindModuleCall {
			b.dropped.Nodes[n.Kind]++
		}
	}
}

// first returns the first value that is not empty.
func first(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// commonest returns the value of the most nodes, the smallest on a tie.
func commonest(nodes []snapshot.Node, of func(snapshot.Node) string) string {
	count := map[string]int{}
	for _, n := range nodes {
		if v := of(n); v != "" {
			count[v]++
		}
	}
	best := ""
	for v, c := range count {
		if best == "" || c > count[best] || (c == count[best] && v < best) {
			best = v
		}
	}
	return best
}

// unanimous returns the value all the nodes have, or "" if they differ.
func unanimous(nodes []snapshot.Node, of func(snapshot.Node) string) string {
	var out string
	for i, n := range nodes {
		v := of(n)
		if i > 0 && v != out {
			return ""
		}
		out = v
	}
	return out
}

// order puts the nodes in a fixed order, modules first, by what the document
// says of them, and then by node id, so that the same snapshot always gives
// the same document whatever order its rows came in. It then fills in the
// parents.
func (b *builder) order() {
	slices.SortFunc(b.items, func(x, y item) int {
		a, c := x.node, y.node
		return cmpAll(
			strings.Compare(a.Kind, c.Kind), // module before resource
			strings.Compare(a.Account, c.Account),
			strings.Compare(a.Root, c.Root),
			strings.Compare(first(a.ModuleAddress, a.Address), first(c.ModuleAddress, c.Address)),
			strings.Compare(a.Type, c.Type),
			strings.Compare(a.ID, c.ID),
			strings.Compare(x.id, y.id),
		)
	})
	b.index = make(map[string]int, len(b.items))
	b.graph.Nodes = make([]Node, len(b.items))
	for i, it := range b.items {
		b.index[it.id] = i
		b.graph.Nodes[i] = it.node
	}
}

func cmpAll(cs ...int) int {
	for _, c := range cs {
		if c != 0 {
			return c
		}
	}
	return 0
}

// edges maps the snapshot's edges. A depends_on edge between two nodes of the
// document is a reference, and a contained_in edge from a resource to a module
// call in the document is the resource's parent. The rest cannot be said.
func (b *builder) edges() {
	seen := map[Edge]bool{}
	for _, e := range b.l.Tables.Edges {
		from, fromOK := b.index[e.FromID]
		to, toOK := b.index[e.ToID]
		switch {
		case !fromOK || !toOK:
		case e.Kind == snapshot.EdgeDependsOn:
			if from != to {
				seen[Edge{From: from, To: to}] = true
			}
			continue
		case e.Kind == snapshot.EdgeContainedIn && b.graph.Nodes[from].Kind == nodeResource && b.graph.Nodes[to].Kind == nodeModule:
			// A resource has one parent; if the snapshot says several, the
			// first in the document's order, and the others are left out.
			if p := b.graph.Nodes[from].Parent; p == nil || to < *p {
				b.graph.Nodes[from].Parent = &to
				continue
			}
			if *b.graph.Nodes[from].Parent == to {
				continue
			}
		}
		b.dropped.Edges[e.Kind]++
	}
	for e := range seen {
		b.graph.Edges = append(b.graph.Edges, e)
	}
	slices.SortFunc(b.graph.Edges, func(x, y Edge) int {
		return cmpAll(x.From-y.From, x.To-y.To)
	})
}
