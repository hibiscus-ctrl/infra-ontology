// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// Edge bases written for can_read and can_write, from iam-lens results.
const (
	// BasisIAMLens: iam-lens judged the principal allowed, with no condition
	// in the result.
	BasisIAMLens = "iam_lens"
	// BasisIAMLensCondition: the result carries a condition (or a note that a
	// condition was ignored), which is not evaluated here and not kept.
	BasisIAMLensCondition = "iam_lens_condition"
	// BasisIAMLensPublic: the principal is anonymous (unsigned access) or "*":
	// anyone. Inferred, as a wildcard principal of a trust policy is.
	BasisIAMLensPublic = "iam_lens_public"
	// BasisIAMLensPublicCondition: public access, and the result carries a
	// condition, which is not evaluated here and not kept: kept apart from
	// access that has none.
	BasisIAMLensPublicCondition = "iam_lens_public_condition"
	// BasisIAMLensCrossAccount: the principal is a role or user of an account
	// other than the resource's: inferred, as for a trust policy, since this
	// snapshot does not read the policies of that account.
	BasisIAMLensCrossAccount = "iam_lens_cross_account"
	// BasisIAMLensUnknownAccount: the resource's account is not known, so the
	// principal may be of another.
	BasisIAMLensUnknownAccount = "iam_lens_unknown_account"
	// BasisIAMLensAccount: the principal is an account (its :root), so any
	// principal in it that its own policies allow.
	BasisIAMLensAccount = "iam_lens_account"
)

// The caps on what an iam-lens file may hold. A file past one is a failed
// source with no edge, and the rest of the snapshot is built.
const (
	maxAccessBytes   = 32 << 20
	maxAccessResults = 10000  // results (one resource each) in a file
	maxAccessEntries = 200000 // allowed principal and action pairs in a file
	// maxAccessEdges is the most can_read and can_write edges a snapshot gets
	// from every file; maxAccessPrincipals the most distinct principals they
	// may name. What is past them is counted, not written.
	maxAccessEdges      = 100000
	maxAccessPrincipals = 10000
	maxARNLen           = 2048
	// What every file together may hold: past either, a file is a failed
	// source with no edge, taking the files in the order of their locations.
	maxAccessTotalBytes   = 128 << 20
	maxAccessTotalEntries = 500000
)

// AccessEntry is one allowed pair of a principal and an action on the resource
// of a result: what is kept of an entry of iam-lens's `allowed` list. The
// conditions, the grant details and the resource patterns of the entry are not
// kept, only whether there were any.
type AccessEntry struct {
	Principal, Service, Action, Level string
	// Conditional says the entry has conditions, or ignored conditions, or
	// depends on the role session's name.
	Conditional bool
	// Patterns says the entry is for resource patterns, which the request
	// had wildcards for: it names no one resource.
	Patterns bool
}

// AccessResult is one `iam-lens who-can` response for one resource.
type AccessResult struct {
	// Resource is the ARN the who-can was asked about.
	Resource string
	Entries  []AccessEntry
	// Incomplete says iam-lens found no collected data for an account, an
	// organization, an organizational unit or a principal the resource's policy
	// names, so that who may reach it is not all it says.
	Incomplete bool
	// Scoped says iam-lens did not check every account (its
	// allAccountsChecked is false: a run limited to some accounts or
	// principals), so that who may reach the resource is not all it lists.
	Scoped bool
}

// Access is what one file of iam-lens results holds.
type Access struct {
	Results []AccessResult
	// Digest is the SHA-256 of what is kept of the file.
	Digest string
}

// AccessRead is what one iam-lens file held, or why it could not be read.
type AccessRead struct {
	Location string
	Doc      Access
	Err      error
}

// ReadAccessFiles reads each file, in the order of their locations, and holds
// all of them to the total caps: a file that fails, or is past a cap, is
// recorded and does not stop the rest. A location given twice is read once.
func ReadAccessFiles(files []string) []AccessRead {
	return readAccessFiles(files, maxAccessTotalBytes, maxAccessTotalEntries)
}

func readAccessFiles(files []string, maxBytes, maxEntries int) []AccessRead {
	sorted := append([]string(nil), files...)
	sort.Strings(sorted)
	reads := make([]AccessRead, 0, len(sorted))
	bytesLeft, entriesLeft := maxBytes, maxEntries
	for i, f := range sorted {
		if i > 0 && f == sorted[i-1] {
			reads = append(reads, reads[len(reads)-1])
			continue
		}
		r := AccessRead{Location: f}
		var n int
		r.Doc, n, r.Err = readAccess(f, bytesLeft)
		bytesLeft -= n
		if r.Err == nil {
			entries := 0
			for _, res := range r.Doc.Results {
				entries += len(res.Entries)
			}
			if entries > entriesLeft {
				r.Doc, r.Err = Access{}, fmt.Errorf("past the total of %d entries that all iam-lens files together may hold", maxEntries)
			} else {
				entriesLeft -= entries
			}
		}
		reads = append(reads, r)
	}
	return reads
}

// ReadAccess reads the file at path as ParseAccess does, up to the size cap.
func ReadAccess(path string) (Access, error) {
	doc, _, err := readAccess(path, maxAccessBytes)
	return doc, err
}

// readAccess reads a file of at most maxAccessBytes and of at most left bytes
// (what is left of the total), and says how many bytes it read.
func readAccess(path string, left int) (Access, int, error) {
	limit := min(maxAccessBytes, left)
	if limit <= 0 {
		return Access{}, 0, fmt.Errorf("past the total of %d MiB that all iam-lens files together may be", maxAccessTotalBytes>>20)
	}
	f, err := os.Open(path)
	if err != nil {
		return Access{}, 0, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return Access{}, len(raw), err
	}
	if len(raw) > limit {
		n := limit
		if limit < maxAccessBytes {
			return Access{}, n, fmt.Errorf("past the total of %d MiB that all iam-lens files together may be", maxAccessTotalBytes>>20)
		}
		return Access{}, n, fmt.Errorf("larger than %d MiB, which an iam-lens file may not be", maxAccessBytes>>20)
	}
	doc, err := ParseAccess(raw)
	return doc, len(raw), err
}

// present is a member whose content is not read, only whether it is there
// and not null: a condition's keys and values are never kept.
type present bool

func (p *present) UnmarshalJSON(b []byte) error {
	*p = present(!bytes.Equal(bytes.TrimSpace(b), []byte("null")))
	return nil
}

// rawAccessEntry is the projection of an entry of iam-lens's `allowed` list
// (its WhoCanAllowed) that is read: the decoder skips every other member, so
// nothing it does not name can reach a snapshot.
type rawAccessEntry struct {
	Principal            *string `json:"principal"`
	Service              string  `json:"service"`
	Action               string  `json:"action"`
	Level                *string `json:"level"`
	Conditions           present `json:"conditions"`
	IgnoredConditions    present `json:"ignoredConditions"`
	DependsOnSessionName bool    `json:"dependsOnSessionName"`
	AllowedPatterns      present `json:"allowedPatterns"`
}

// rawAccessResult is one item of a file: the resource a who-can was asked
// about, and the response (iam-lens's WhoCanResponse).
type rawAccessResult struct {
	Resource *string `json:"resource"`
	Result   *struct {
		Allowed                     *entryList `json:"allowed"`
		AllAccountsChecked          *bool      `json:"allAccountsChecked"`
		AccountsNotFound            []string   `json:"accountsNotFound"`
		OrganizationsNotFound       []string   `json:"organizationsNotFound"`
		OrganizationalUnitsNotFound []string   `json:"organizationalUnitsNotFound"`
		PrincipalsNotFound          []string   `json:"principalsNotFound"`
	} `json:"result"`
}

// entryList is the `allowed` list of a response. It is read one entry at a
// time, as the entries are kept and not the decoded members, and it stops at
// the cap: a list of millions of entries is never held.
type entryList []AccessEntry

func (l *entryList) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('[') {
		return errors.New("\"allowed\" is not a list")
	}
	*l = entryList{}
	for dec.More() {
		if len(*l) >= maxAccessEntries {
			return fmt.Errorf("more than %d entries", maxAccessEntries)
		}
		var e rawAccessEntry
		if err := dec.Decode(&e); err != nil {
			return err
		}
		if e.Principal == nil || e.Level == nil || *e.Principal == "" {
			return fmt.Errorf("entry %d: a principal and a level are required", len(*l))
		}
		*l = append(*l, AccessEntry{
			Principal: *e.Principal, Service: e.Service, Action: e.Action, Level: *e.Level,
			Conditional: bool(e.Conditions) || bool(e.IgnoredConditions) || e.DependsOnSessionName,
			Patterns:    bool(e.AllowedPatterns),
		})
	}
	return nil
}

// ParseAccess reads iam-lens results. iam-lens's `who-can` prints the response
// as JSON and does not say which resource it was asked about, so a file holds,
// for each resource, an object {"resource": ARN, "result": the response}: one
// object, an array of them, or several objects one after another (JSON Lines).
// A file of another shape, an item without a resource or a response, an entry
// without a principal or a level, or a file past the caps is an error.
func ParseAccess(raw []byte) (Access, error) {
	shape := func(err error) error { return fmt.Errorf("not JSON of the expected shape: %w", err) }
	dec := json.NewDecoder(bytes.NewReader(raw))
	var items []rawAccessResult
	add := func(it rawAccessResult) error {
		if items = append(items, it); len(items) > maxAccessResults {
			return fmt.Errorf("more than %d results", maxAccessResults)
		}
		return nil
	}
	for {
		// A value is an array when its first byte is '[': read its items one
		// at a time, so that the cap stops a file of millions of them.
		rest := raw[dec.InputOffset():]
		rest = bytes.TrimLeft(rest, " \t\r\n")
		if len(rest) == 0 {
			break
		}
		if rest[0] == '[' {
			if _, err := dec.Token(); err != nil {
				return Access{}, shape(err)
			}
			for dec.More() {
				var it rawAccessResult
				if err := dec.Decode(&it); err != nil {
					return Access{}, shape(err)
				}
				if err := add(it); err != nil {
					return Access{}, err
				}
			}
			if _, err := dec.Token(); err != nil {
				return Access{}, shape(err)
			}
			continue
		}
		var it rawAccessResult
		if err := dec.Decode(&it); err != nil {
			return Access{}, shape(err)
		}
		if err := add(it); err != nil {
			return Access{}, err
		}
	}
	if len(items) == 0 {
		return Access{}, errors.New("no results")
	}
	var doc Access
	entries := 0
	for i, it := range items {
		if it.Resource == nil || it.Result == nil || it.Result.Allowed == nil {
			return Access{}, fmt.Errorf("result %d: needs a \"resource\" and a \"result\" with an \"allowed\" list: wrap each who-can output as {\"resource\": ARN, \"result\": output}", i)
		}
		r := AccessResult{
			Resource: *it.Resource, Entries: *it.Result.Allowed,
			Incomplete: len(it.Result.AccountsNotFound)+len(it.Result.OrganizationsNotFound)+
				len(it.Result.OrganizationalUnitsNotFound)+len(it.Result.PrincipalsNotFound) > 0,
			Scoped: it.Result.AllAccountsChecked != nil && !*it.Result.AllAccountsChecked,
		}
		if entries += len(r.Entries); entries > maxAccessEntries {
			return Access{}, fmt.Errorf("more than %d entries", maxAccessEntries)
		}
		sort.Slice(r.Entries, func(a, b int) bool { return lessEntry(r.Entries[a], r.Entries[b]) })
		doc.Results = append(doc.Results, r)
	}
	// A full key, the resource and then what the result holds, so that the
	// digest does not depend on the order the results came in.
	sort.Slice(doc.Results, func(a, b int) bool { return lessResult(doc.Results[a], doc.Results[b]) })
	doc.Digest = accessDigest(doc)
	return doc, nil
}

func lessResult(a, b AccessResult) bool {
	if a.Resource != b.Resource {
		return a.Resource < b.Resource
	}
	if a.Incomplete != b.Incomplete {
		return !a.Incomplete
	}
	if a.Scoped != b.Scoped {
		return !a.Scoped
	}
	for i := 0; i < len(a.Entries) && i < len(b.Entries); i++ {
		if lessEntry(a.Entries[i], b.Entries[i]) {
			return true
		}
		if lessEntry(b.Entries[i], a.Entries[i]) {
			return false
		}
	}
	return len(a.Entries) < len(b.Entries)
}

func lessEntry(a, b AccessEntry) bool {
	if a.Principal != b.Principal {
		return a.Principal < b.Principal
	}
	if a.Service != b.Service {
		return a.Service < b.Service
	}
	if a.Action != b.Action {
		return a.Action < b.Action
	}
	if a.Level != b.Level {
		return a.Level < b.Level
	}
	if a.Conditional != b.Conditional {
		return !a.Conditional
	}
	return !a.Patterns && b.Patterns
}

// accessDigest is the SHA-256 of what is kept of a file, in a fixed order: like
// a state's, not the hash of the file's bytes.
func accessDigest(d Access) string {
	h := sha256.New()
	w := func(fields ...string) {
		for _, f := range fields {
			h.Write([]byte(f))
			h.Write([]byte{0})
		}
		h.Write([]byte{'\n'})
	}
	flag := func(b bool) string {
		if b {
			return "1"
		}
		return "0"
	}
	w("iam-lens")
	for _, r := range d.Results {
		w("resource", r.Resource, flag(r.Incomplete), flag(r.Scoped))
		for _, e := range r.Entries {
			w(e.Principal, e.Service, e.Action, e.Level, flag(e.Conditional), flag(e.Patterns))
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}

func accessSourceID(location string) string {
	sum := sha256.Sum256([]byte(location))
	return "iam-lens-" + hex.EncodeToString(sum[:])[:12]
}

// accessState counts what the iam-lens results held that no edge was made of,
// for the manifest's limits.
type accessState struct {
	files, failed, results int
	notFound, rejected     int // results about a resource the snapshot lacks, or not a concrete ARN
	incomplete, scoped     int // results that name data iam-lens lacked, and results of a run that did not check every account
	duplicates             int // --iam-lens locations given more than once
	hashedARNs             int // AWS resources of a hashed inventory, which no ARN can be matched to
	levels, patterns       int // entries of a level or a service that make no edge, and entries for patterns
	skipped, rejectedP     int // principals not turned into edges, and principals not of the shape they say
	cappedEdges            int
	cappedPrincipals       int
	edges                  int
}

// accessKind is the edge kind an action's level makes: reading and listing
// make can_read; writing, tagging and changing permissions make can_write.
// sts actions are about assuming a role, which can_assume says; any other
// level makes no edge.
func accessKind(service, level string) string {
	if strings.EqualFold(service, "sts") {
		return ""
	}
	switch strings.ToLower(level) {
	case "read", "list":
		return snapshot.EdgeCanRead
	case "write", "tagging", "permissions management":
		return snapshot.EdgeCanWrite
	}
	return ""
}

// validARN says s is a concrete ARN: it has the six parts, a bounded length,
// no control characters and no wildcard.
func validARN(s string) bool {
	if len(s) > maxARNLen || !strings.HasPrefix(s, "arn:") || strings.ContainsAny(s, "*?") {
		return false
	}
	if strings.Count(s, ":") < 5 {
		return false
	}
	return !hasControl(s)
}

// hasControl says s holds a control character, which no ARN or principal does.
func hasControl(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// resourceARNs maps the ARN of each AWS resource of the snapshot to its node,
// as the roles and users are in trust.arns: a thing a state manages beats a
// data source or an inventory listing of the same ARN, and among equals the
// lowest ID wins.
func (b *builder) resourceARNs() map[string]string {
	byARN := map[string]string{}
	b.access.hashedARNs = 0
	for id, n := range b.nodes {
		if n.Kind != snapshot.KindResource || n.Cloud != "aws" || n.ARNOrPath == "" {
			continue
		}
		if b.preHashed[id+"\x00arn_or_path"] {
			// An inventory written with --hash-ids: its ARN is a hash, which
			// no ARN of a result can be matched to.
			b.access.hashedARNs++
			continue
		}
		if old, ok := byARN[n.ARNOrPath]; ok {
			if o := b.nodes[old]; arnRank(o) < arnRank(n) || arnRank(o) == arnRank(n) && old < id {
				continue
			}
		}
		byARN[n.ARNOrPath] = id
	}
	return byARN
}

type accessKey struct{ kind, principal, resource string }

// accessVal is what the entries for one edge say: whether every one of them
// has a condition, and the source of the one kept.
type accessVal struct {
	conditional bool
	source      string
}

// better says a is the value to keep over c: an unconditional entry over a
// conditional one, and among equals the lowest source, so that the order files
// and entries came in changes nothing.
func (a accessVal) better(c accessVal) bool {
	if a.conditional != c.conditional {
		return !a.conditional
	}
	return a.source < c.source
}

// isPublic says a principal of an iam-lens entry is anyone: "anonymous"
// (unsigned access) or "*".
func isPublic(principal string) bool { return principal == "anonymous" || principal == "*" }

// accessBasis is the basis and confidence of an edge, from where the principal
// starts it (as a trust policy's does: a role of another account, or an
// account, is inferred) and from the entries having conditions. A condition
// is not evaluated: it makes the edge inferred.
func accessBasis(ref principalRef, public, conditional bool) (basis, conf string) {
	switch {
	case public && conditional:
		return BasisIAMLensPublicCondition, snapshot.Inferred
	case public:
		return BasisIAMLensPublic, snapshot.Inferred
	case conditional:
		return BasisIAMLensCondition, snapshot.Inferred
	}
	switch {
	case ref.basis == BasisTrustCrossAccount:
		return BasisIAMLensCrossAccount, snapshot.Inferred
	case ref.basis == BasisTrustAccount:
		return BasisIAMLensAccount, snapshot.Inferred
	case ref.conf == snapshot.Inferred:
		return BasisIAMLensUnknownAccount, snapshot.Inferred
	}
	return BasisIAMLens, ref.conf
}

// addAccess adds a can_read or can_write edge, from each principal an iam-lens
// result names to the resource it was asked about, for the resources the
// snapshot holds. It runs after the trust edges, so that a role or user the
// snapshot holds is found by its ARN. A resource the snapshot lacks makes no
// node: the result is counted. A principal it lacks gets an external
// placeholder, as a principal of a trust policy does.
func (b *builder) addAccess(reads []AccessRead) {
	if len(reads) == 0 {
		return
	}
	byARN := b.resourceARNs()
	sorted := append([]AccessRead(nil), reads...)
	sort.SliceStable(sorted, func(i, j int) bool { return Sanitise(sorted[i].Location) < Sanitise(sorted[j].Location) })
	agg := map[accessKey]accessVal{}
	seen := map[string]bool{}
	for _, r := range sorted {
		loc := Sanitise(r.Location)
		src := snapshot.Source{
			SourceID: b.accessSourceID(loc), Kind: snapshot.SourceIAMLens, Backend: BackendFile, Location: loc,
			CollectedAt: b.at(), Collector: b.o.Collector, CollectorVersion: b.o.CollectorVersion,
			Status: snapshot.StatusOK,
		}
		if seen[src.SourceID] {
			b.access.duplicates++
			continue
		}
		seen[src.SourceID] = true
		if r.Err != nil {
			src.Status, src.Reason = snapshot.StatusFailed, Scrub(r.Err.Error())
			b.access.failed++
			b.sources = append(b.sources, src)
			continue
		}
		src.DocumentSHA256 = r.Doc.Digest
		b.sources = append(b.sources, src)
		b.access.files++
		for _, res := range r.Doc.Results {
			b.access.results++
			if res.Incomplete {
				b.access.incomplete++
			}
			if res.Scoped {
				b.access.scoped++
			}
			if !validARN(res.Resource) {
				b.access.rejected++
				continue
			}
			to, ok := byARN[res.Resource]
			if !ok {
				b.access.notFound++
				continue
			}
			for _, e := range res.Entries {
				kind := accessKind(e.Service, e.Level)
				switch {
				case e.Patterns:
					b.access.patterns++
					continue
				case kind == "":
					b.access.levels++
					continue
				}
				v := accessVal{e.Conditional, src.SourceID}
				// "*" and "anonymous" are one principal: anyone.
				principal := e.Principal
				if isPublic(principal) {
					principal = "anonymous"
				}
				k := accessKey{kind, principal, to}
				if old, ok := agg[k]; !ok || v.better(old) {
					agg[k] = v
				}
			}
		}
	}
	keys := make([]accessKey, 0, len(agg))
	for k := range agg {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, c := keys[i], keys[j]
		if a.principal != c.principal {
			return a.principal < c.principal
		}
		if a.kind != c.kind {
			return a.kind < c.kind
		}
		return a.resource < c.resource
	})
	// A principal is resolved for the account of the resource it reaches, as a
	// trust policy's is for the role's: a role of another account is
	// inferred. The distinct principals are what the cap counts.
	type resolvedKey struct{ principal, account string }
	type resolved struct {
		ref     principalRef
		outcome int
	}
	resolvedBy := map[resolvedKey]resolved{}
	distinct := map[string]bool{}
	for _, k := range keys {
		v := agg[k]
		account := b.resourceAccount(k.resource)
		rk := resolvedKey{k.principal, account}
		p, ok := resolvedBy[rk]
		if !ok {
			if !distinct[k.principal] && len(distinct) >= maxAccessPrincipals {
				b.access.cappedPrincipals++
				continue
			}
			distinct[k.principal] = true
			ref, outcome := b.principal(&docState{source: v.source}, accessPrincipal(k.principal), account)
			p = resolved{ref, outcome}
			resolvedBy[rk] = p
		}
		switch {
		case p.outcome == principalRejected:
			b.access.rejectedP++
		case p.outcome != principalEdge:
			b.access.skipped++
		case b.access.edges >= maxAccessEdges:
			b.access.cappedEdges++
		default:
			basis, conf := accessBasis(p.ref, isPublic(k.principal), v.conditional)
			b.addEdge(k.kind, basis, conf, p.ref.id, k.resource, v.source)
			b.access.edges++
		}
	}
}

// resourceAccount is the account of a resource of the snapshot: the one its
// ARN names where it has one (an S3 bucket's has none), else the one its node
// has, else none.
func (b *builder) resourceAccount(id string) string {
	n := b.nodes[id]
	if parts := strings.SplitN(n.ARNOrPath, ":", 6); len(parts) == 6 && accountID.MatchString(parts[4]) {
		return parts[4]
	}
	return n.Account
}

// accessPrincipal reads the principal of an iam-lens entry (an ARN, a service
// name or "anonymous") as a principal of a trust policy. What is none of these
// is left as a bare string, which principal rejects.
func accessPrincipal(s string) tfstate.TrustPrincipal {
	switch {
	case len(s) > maxPrincipalLen || hasControl(s):
		return tfstate.TrustPrincipal{Type: "*", Value: "rejected"}
	case s == "anonymous" || s == "*":
		return tfstate.TrustPrincipal{Type: "*", Value: "*"}
	case strings.Contains(s, "*"):
		// A pattern is not a principal: iam-lens names the ones it found.
		return tfstate.TrustPrincipal{Type: "*", Value: s}
	case strings.HasPrefix(s, "arn:"):
		return tfstate.TrustPrincipal{Type: "AWS", Value: s}
	case servicePrincipal.MatchString(strings.ToLower(s)):
		return tfstate.TrustPrincipal{Type: "Service", Value: s}
	}
	return tfstate.TrustPrincipal{Type: "*", Value: s}
}

// accessLimits is what the can_read and can_write edges leave out, for the
// manifest.
func (b *builder) accessLimits() []string {
	a := b.access
	if a.files == 0 && a.failed == 0 {
		return nil
	}
	s := []string{"can_read and can_write edges come only from iam-lens results read from a file: infra-ontology does not run iam-lens, read policies or call the cloud, so an edge says iam-lens judged the principal allowed on the IAM data it was given, which this snapshot does not hold and which may be older than the rest of it. can_read and can_write mean only that iam-lens classes an action the principal is allowed as Read or List (can_read), or as Write, Tagging or Permissions management (can_write): they do not say the principal can read or write the data in the resource, since those levels include metadata reads such as s3:GetBucketLocation and actions such as lambda:InvokeFunction, kms:Decrypt, sns:Publish, sqs:SendMessage and iam:PassRole. Another level of action and any sts action make no edge. A result with a condition makes an inferred edge, and the condition is not kept; public access (anonymous or *), a principal of another account or of an account not known, and an account principal make inferred edges too. Only the resources the snapshot holds have edges."}
	if a.failed > 0 {
		s = append(s, fmt.Sprintf("%d iam-lens files could not be read, or were past the size caps, and have no edges.", a.failed))
	}
	if a.notFound > 0 {
		s = append(s, fmt.Sprintf("%d iam-lens results are for a resource this snapshot does not hold, and have no edge.", a.notFound))
	}
	if a.rejected > 0 {
		s = append(s, fmt.Sprintf("%d iam-lens results are for a resource that is not a concrete ARN (a wildcard, or too long), and have no edge.", a.rejected))
	}
	if a.duplicates > 0 {
		s = append(s, fmt.Sprintf("%d iam-lens locations were given more than once and were read once.", a.duplicates))
	}
	if a.hashedARNs > 0 {
		s = append(s, fmt.Sprintf("%d AWS resources of an inventory written with --hash-ids have an ARN that is a hash, which no iam-lens resource can be matched to: results for them are not edges, and some of the results counted above as for a resource this snapshot does not hold may be for them.", a.hashedARNs))
	}
	if a.scoped > 0 {
		s = append(s, fmt.Sprintf("%d iam-lens results say they did not check every account (allAccountsChecked is false: a run limited by a principal scope or to some accounts), so who can reach the resource is not all they list.", a.scoped))
	}
	if a.incomplete > 0 {
		s = append(s, fmt.Sprintf("%d iam-lens results say they found no collected data for an account, organization or principal the resource's policy names, so who can reach the resource is not all they list.", a.incomplete))
	}
	if a.patterns > 0 {
		s = append(s, fmt.Sprintf("%d iam-lens entries are for resource patterns, which name no one resource, and make no edge.", a.patterns))
	}
	if a.levels > 0 {
		s = append(s, fmt.Sprintf("%d iam-lens entries are for an action of a level that makes no edge, or an sts action.", a.levels))
	}
	if n := a.skipped + a.rejectedP; n > 0 {
		s = append(s, fmt.Sprintf("%d principals of iam-lens results (sessions, ARNs of other services, strings that are not a principal) are not turned into edges.", n))
	}
	if a.cappedEdges > 0 || a.cappedPrincipals > 0 {
		s = append(s, fmt.Sprintf("the caps of %d can_read and can_write edges and %d principals were reached: %d edges are left out.", maxAccessEdges, maxAccessPrincipals, a.cappedEdges+a.cappedPrincipals))
	}
	return s
}

// accessSourceID is the identifier of the source of an iam-lens file, from the
// hash of its location where there is a key.
func (b *builder) accessSourceID(location string) string { return accessSourceID(b.h(location)) }
