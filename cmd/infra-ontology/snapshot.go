// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/IgnatG/infraharvest/pkg/secretscan"

	"github.com/hibiscus-ctrl/infra-ontology/internal/ingest"
	"github.com/hibiscus-ctrl/infra-ontology/internal/signing"
	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
	"github.com/hibiscus-ctrl/infra-ontology/internal/version"
)

// newFlags makes a flag set that reports its own errors on stderr and lets run
// return the usage code.
func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet("infra-ontology "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// parse reads the flags (which may come after the folders) and returns the
// folders, or false if the command line was wrong.
func parse(fs *flag.FlagSet, args []string, lo, hi int, stderr io.Writer) ([]string, bool) {
	var rest []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, false
		}
		if fs.NArg() == 0 {
			break
		}
		rest = append(rest, fs.Arg(0))
		args = fs.Args()[1:]
	}
	if len(rest) < lo || len(rest) > hi {
		fmt.Fprintf(stderr, "%s: want %s folder(s), got %d\n", fs.Name(), countWord(lo, hi), len(rest))
		return nil, false
	}
	return rest, true
}

func countWord(lo, hi int) string {
	if lo == hi {
		return fmt.Sprint(lo)
	}
	return fmt.Sprintf("%d or %d", lo, hi)
}

func writeJSON(w io.Writer, v any) {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// runVerify is `snapshot verify`: the manifest, the tables and the rows, and
// the signature when there is one. A signature that is not valid fails it. No
// signature fails it only when one is required: --require-signature, or a
// --key or --certificate-identity to trust, which the signature must satisfy.
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("snapshot verify", stderr)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	vf := addVerifyFlags(fs)
	dirs, ok := parse(fs, args, 1, 1, stderr)
	if !ok {
		return exitUsage
	}
	v, err := vf.check()
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot verify: %v\n", err)
		return exitUsage
	}
	// The signature is checked over the manifest bytes the verification read.
	res, manifest := snapshot.VerifyWithManifest(dirs[0])
	sig := signing.CheckBytes(dirs[0], manifest, v)
	if problem := signatureProblem(sig, vf.required()); problem != "" {
		res.Problems = append(res.Problems, problem)
	}
	switch {
	case *asJSON:
		writeJSON(stdout, struct {
			OK bool `json:"ok"`
			snapshot.VerifyResult
			Signature signing.Status `json:"signature"`
		}{res.OK(), res, sig})
	case res.OK():
		fmt.Fprintf(stdout, "ok: %s\n  snapshot  %s\n", res.Dir, res.SnapshotID)
		if res.ParentID != "" {
			fmt.Fprintf(stdout, "  parent    %s\n", res.ParentID)
		}
		if res.Label != "" {
			fmt.Fprintf(stdout, "  label     %s\n", res.Label)
		}
		for _, t := range res.Tables {
			fmt.Fprintf(stdout, "  %-9s %d rows, sha256 %s\n", t.Name, t.Rows, t.SHA256)
		}
		fmt.Fprintf(stdout, "  signature %s\n", printable(sig.String()))
		if sig.State == signing.SignedUnverified {
			fmt.Fprintln(stdout, "            not checked: give --key, or --certificate-identity and --certificate-oidc-issuer")
		}
	default:
		fmt.Fprintf(stdout, "FAILED: %s does not verify\n", res.Dir)
		for _, p := range res.Problems {
			fmt.Fprintf(stdout, "  - %s\n", printable(p))
		}
	}
	if !res.OK() {
		return exitVerifyFailed
	}
	return exitOK
}

// runDiff is `diff`.
func runDiff(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("diff", stderr)
	asJSON := fs.Bool("json", false, "print the result as JSON")
	dirs, ok := parse(fs, args, 1, 2, stderr)
	if !ok {
		return exitUsage
	}
	from, to := dirs[0], ""
	if len(dirs) == 2 {
		to = dirs[1]
	} else {
		// One folder: what changed in it since its parent.
		parent, err := snapshot.FindParent(dirs[0])
		switch {
		case err != nil:
			fmt.Fprintf(stderr, "infra-ontology diff: %v\n", err)
			return exitFailed
		case parent == "":
			fmt.Fprintf(stderr, "infra-ontology diff: %s has no parent snapshot; give a second folder\n", dirs[0])
			return exitFailed
		}
		from, to = parent, dirs[0]
	}
	a, err := snapshot.Load(from)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology diff: %v\n", err)
		return exitVerifyFailed
	}
	b, err := snapshot.Load(to)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology diff: %v\n", err)
		return exitVerifyFailed
	}
	d := snapshot.DiffSnapshots(a, b)
	if *asJSON {
		writeJSON(stdout, d)
		return exitOK
	}
	printDiff(stdout, d, a, b)
	return exitOK
}

func printDiff(w io.Writer, d snapshot.Diff, a, b *snapshot.Loaded) {
	fmt.Fprintf(w, "from %s%s\n", short(d.From), labelOf(a.Manifest))
	fmt.Fprintf(w, "to   %s%s\n", short(d.To), labelOf(b.Manifest))
	if d.Summary.Empty() {
		fmt.Fprintln(w, "no changes")
		return
	}
	s := d.Summary
	fmt.Fprintf(w, "nodes: %d added, %d removed, %d changed\n", s.NodesAdded, s.NodesRemoved, s.NodesChanged)
	for _, n := range d.Nodes.Added {
		fmt.Fprintf(w, "  + %s\n", describe(n))
	}
	for _, n := range d.Nodes.Removed {
		fmt.Fprintf(w, "  - %s\n", describe(n))
	}
	for _, n := range d.Nodes.Changed {
		fmt.Fprintf(w, "  ~ %s: %s\n", describe(n.NodeRef), printable(strings.Join(n.Fields, ", ")))
	}
	fmt.Fprintf(w, "edges: %d added, %d removed, %d changed\n", s.EdgesAdded, s.EdgesRemoved, s.EdgesChanged)
	for _, e := range d.Edges.Added {
		fmt.Fprintf(w, "  + %s\n", edge(e))
	}
	for _, e := range d.Edges.Removed {
		fmt.Fprintf(w, "  - %s\n", edge(e))
	}
	for _, e := range d.Edges.Changed {
		fmt.Fprintf(w, "  ~ %s: %s\n", edge(e.EdgeRef), printable(strings.Join(e.Fields, ", ")))
	}
}

func short(id string) string { return printable(id[:min(12, len(id))]) }

// printable escapes control characters, so a value read from a snapshot
// cannot move the cursor, recolour or rewrite the terminal it is printed to.
func printable(s string) string {
	// Decide on the bytes as well as the runes: an invalid byte such as a
	// lone 0x9b decodes to U+FFFD, yet some terminals read it as an escape.
	if utf8.ValidString(s) && !strings.ContainsFunc(s, func(r rune) bool {
		return unicode.IsControl(r) || unicode.Is(unicode.Cf, r)
	}) {
		return s
	}
	q := strconv.QuoteToGraphic(s)
	return q[1 : len(q)-1]
}

func labelOf(m snapshot.Manifest) string {
	if m.Label == "" {
		return ""
	}
	return " (" + printable(m.Label) + ")"
}

func describe(n snapshot.NodeRef) string {
	label := printable(first(n.Address, n.Name, short(n.NodeID)))
	typ := printable(first(n.Type, n.Kind))
	if n.Account != "" {
		return fmt.Sprintf("%s %s [%s]", typ, label, printable(n.Account))
	}
	return typ + " " + label
}

func edge(e snapshot.EdgeRef) string {
	return fmt.Sprintf("%s: %s -> %s", printable(e.Kind), printable(first(e.FromLabel, short(e.FromID))), printable(first(e.ToLabel, short(e.ToID))))
}

func first(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// estateFile is the JSON `snapshot build --from-json` reads. It is the rows of
// the three tables, plus what the manifest says about itself. Unknown members
// are an error, so a file with attribute values in it is refused.
type estateFile struct {
	CreatedAt string              `json:"created_at"`
	ParentID  string              `json:"parent_id"`
	Label     string              `json:"label"`
	Limits    string              `json:"limits"`
	Redaction *snapshot.Redaction `json:"redaction"`
	Nodes     []snapshot.Node     `json:"nodes"`
	Edges     []snapshot.Edge     `json:"edges"`
	Sources   []snapshot.Source   `json:"sources"`
}

// listFlag is a flag that may be given more than once.
type listFlag []string

func (f *listFlag) String() string     { return strings.Join(*f, ", ") }
func (f *listFlag) Set(v string) error { *f = append(*f, v); return nil }

// runBuild is `snapshot build`: from the Terraform state in one or more
// backends (--state) and the inventories infraharvest exported (--inventory),
// or, as a test and development path, from a JSON file of rows (--from-json).
func runBuild(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("snapshot build", stderr)
	var states, inventories, iamLens, dropTags listFlag
	fs.Var(&states, "state", "a Terraform state to read: a path, s3://bucket/prefix, gs://bucket/prefix, azblob://account/container/prefix or hcp://organization/workspace (repeat for more)")
	fs.Var(&inventories, "inventory", "an infraharvest export to read: an inventory/v1 or ocsf-inventory/v1 JSON file (repeat for more)")
	fs.Var(&iamLens, "iam-lens", "a file of iam-lens who-can results, each wrapped as {\"resource\": ARN, \"result\": the output}, to add can_read and can_write edges from (repeat for more; needs --state or --inventory)")
	fs.Var(&dropTags, "drop-tag", "a tag key to drop from the inventories' resources (repeat it, or separate keys with commas)")
	dropAllTags := fs.Bool("drop-tags", false, "drop every tag of the inventories' resources")
	hashIDs := fs.Bool("hash-ids", false, "hash IDs, ARNs, names, Terraform addresses and state locations with HMAC-SHA256, under a key from "+keyEnv+" (or "+secretscan.KeyEnv+") or --hash-key-file")
	hashKeyFile := fs.String("hash-key-file", "", "the file that holds the key --hash-ids hashes with (16 bytes at least)")
	dropAddresses := fs.Bool("drop-addresses", false, "leave Terraform addresses, module paths and the Terraform names of resources and module calls out of the snapshot's nodes, to share it outside the team; node IDs of module calls, data sources and resources without an ID stay unkeyed hashes of state location and address unless --hash-ids is also used")
	from := fs.String("from-json", "", "the JSON file of nodes, edges and sources to build from (test and development path)")
	out := fs.String("out", filepath.Join(".infra-ontology", "snapshots"), "the folder to write the snapshot folder into")
	label := fs.String("label", "", "a name for the snapshot (overrides the file's)")
	parent := fs.String("parent", "", "the id of the snapshot this one follows (overrides the file's)")
	created := fs.String("created-at", "", "when the snapshot is written, as RFC 3339 (default: the file's, else now)")
	if _, ok := parse(fs, args, 0, 0, stderr); !ok {
		return exitUsage
	}
	switch {
	case *from != "" && (len(states) > 0 || len(inventories) > 0 || len(iamLens) > 0):
		fmt.Fprintln(stderr, "infra-ontology snapshot build: give --state, --inventory and --iam-lens, or --from-json, not both")
		return exitUsage
	case *from == "" && len(states) == 0 && len(inventories) == 0:
		fmt.Fprintln(stderr, "infra-ontology snapshot build: --state LOCATION or --inventory FILE is required (or --from-json FILE, for tests)")
		return exitUsage
	case *hashKeyFile != "" && !*hashIDs:
		fmt.Fprintln(stderr, "infra-ontology snapshot build: --hash-key-file is for --hash-ids")
		return exitUsage
	case *hashIDs && *from != "":
		fmt.Fprintln(stderr, "infra-ontology snapshot build: --hash-ids hashes what --state and --inventory read, not --from-json")
		return exitUsage
	case *dropAddresses && *from != "":
		fmt.Fprintln(stderr, "infra-ontology snapshot build: --drop-addresses applies to what --state and --inventory read, not --from-json")
		return exitUsage
	}
	var (
		tables snapshot.Tables
		opts   = snapshot.BuildOptions{
			ParentID: *parent, Label: *label,
			Tool: snapshot.Tool{Name: "infra-ontology", Version: version.Version},
		}
		code int
	)
	opts.CreatedAt = time.Now()
	if *created != "" {
		var err error
		if opts.CreatedAt, err = time.Parse(time.RFC3339, *created); err != nil {
			fmt.Fprintf(stderr, "infra-ontology snapshot build: created_at: %v\n", err)
			return exitUsage
		}
	}
	if *from != "" {
		var est estateFile
		if rc := readEstate(*from, &est, stderr); rc != exitOK {
			return rc
		}
		opts.ParentID, opts.Label, opts.Limits = first(*parent, est.ParentID), first(*label, est.Label), est.Limits
		if est.Redaction != nil {
			opts.Redaction = *est.Redaction
		}
		if at := first(*created, est.CreatedAt); at != "" {
			var err error
			if opts.CreatedAt, err = time.Parse(time.RFC3339, at); err != nil {
				fmt.Fprintf(stderr, "infra-ontology snapshot build: created_at: %v\n", err)
				return exitUsage
			}
		}
		tables = snapshot.Tables{Nodes: est.Nodes, Edges: est.Edges, Sources: est.Sources}
	} else {
		var res ingest.Result
		in := ingest.Options{
			CollectedAt: opts.CreatedAt, Collector: "infra-ontology", CollectorVersion: version.Version,
			DropTags: splitKeys(dropTags), DropAllTags: *dropAllTags, DropAddresses: *dropAddresses,
		}
		if *hashIDs {
			key, err := readHashKey(*hashKeyFile)
			if err != nil {
				fmt.Fprintf(stderr, "infra-ontology snapshot build: %v\n", err)
				return exitUsage
			}
			in.HashKey = key
		}
		if res, code = readSources(states, inventories, iamLens, in, stderr); code != exitOK && code != exitPartial {
			return code
		}
		tables, opts.Limits, opts.Redaction = res.Tables, res.Limits, res.Redaction
	}
	s, err := snapshot.Build(tables, opts)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %v\n", err)
		return exitFailed
	}
	dir, err := s.Write(*out)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %v\n", err)
		return exitFailed
	}
	fmt.Fprintf(stdout, "%s\nsnapshot %s\n", dir, s.Manifest.SnapshotID)
	return code
}

// readEstate decodes the JSON file of rows.
func readEstate(file string, est *estateFile, stderr io.Writer) int {
	raw, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %v\n", err)
		return exitFailed
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(est); err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %s: %v\n", file, err)
		return exitFailed
	}
	return exitOK
}

// readSources reads the states and the inventories the user named. It returns
// exitUsage for a location this build cannot read or a file that is not there,
// exitFailed if nothing could be read and exitPartial if some could not: the
// snapshot then says which.
func readSources(locations, files, access []string, o ingest.Options, stderr io.Writer) (ingest.Result, int) {
	resolved := make([]string, 0, len(locations))
	for _, l := range locations {
		r, err := ingest.Resolve(l)
		if err == nil {
			err = ingest.Check(r)
		}
		if err != nil {
			fmt.Fprintf(stderr, "infra-ontology snapshot build: %v\n", cleanErr(err))
			return ingest.Result{}, exitUsage
		}
		resolved = append(resolved, r)
	}
	for _, f := range files {
		if st, err := os.Stat(f); err != nil || !st.Mode().IsRegular() {
			fmt.Fprintf(stderr, "infra-ontology snapshot build: --inventory %s is not a file\n", ingest.Sanitise(f))
			return ingest.Result{}, exitUsage
		}
	}
	for _, f := range access {
		if st, err := os.Stat(f); err != nil || !st.Mode().IsRegular() {
			fmt.Fprintf(stderr, "infra-ontology snapshot build: --iam-lens %s is not a file\n", ingest.Sanitise(f))
			return ingest.Result{}, exitUsage
		}
	}
	o.Access = ingest.ReadAccessFiles(access)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	res, err := ingest.BuildAll(ingest.ReadAll(ctx, resolved, ingest.Stores()), ingest.ReadInventories(files), o)
	if err != nil {
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %v\n", err)
		return ingest.Result{}, exitFailed
	}
	if res.Failed > 0 {
		what, total := "states could not be read", len(resolved)
		if len(files) > 0 || len(access) > 0 {
			what, total = "sources could not be read in full", len(resolved)+len(files)+len(access)
		}
		fmt.Fprintf(stderr, "infra-ontology snapshot build: %d of %d %s; the snapshot is partial and lists them\n", res.Failed, total, what)
		return res, exitPartial
	}
	return res, exitOK
}

// splitKeys splits the values of --drop-tag, which may hold several keys
// separated by commas.
func splitKeys(values []string) []string {
	var keys []string
	for _, v := range values {
		for k := range strings.SplitSeq(v, ",") {
			if k = strings.TrimSpace(k); k != "" {
				keys = append(keys, k)
			}
		}
	}
	return keys
}

// cleanErr removes credentials from an error before it is printed.
func cleanErr(err error) string { return ingest.Scrub(err.Error()) }

// keyEnv is the environment variable that holds the key --hash-ids hashes
// with, if --hash-key-file does not name a file. INFRAHARVEST_EXPORT_KEY,
// which infraharvest export reads, is read too, so that one key can serve both.
const keyEnv = "INFRA_ONTOLOGY_KEY"

// readHashKey returns the key --hash-ids hashes with: the content of file, or
// else the environment variable keyEnv, or else the one infraharvest export
// reads. It is the key of pkg/secretscan, so that the hashes are the ones
// infraharvest export --hash-ids writes for the same key.
func readHashKey(file string) ([]byte, error) {
	getenv := func(name string) string {
		if name == secretscan.KeyEnv {
			return first(os.Getenv(keyEnv), os.Getenv(name))
		}
		return os.Getenv(name)
	}
	if file == "" && getenv(secretscan.KeyEnv) == "" {
		return nil, fmt.Errorf("--hash-ids needs a key you hold: set %s (or %s), or name a file with --hash-key-file", keyEnv, secretscan.KeyEnv)
	}
	return secretscan.ReadKey(file, getenv)
}
