// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/secretscan"
	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

const accessIAMRoot = "s3://acme-tfstate/prod/iam.tfstate"

// accessReads are the fixture states and a state of two roles and a user, which
// the iam-lens fixture names.
func accessReads(t *testing.T) []Read {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "access", "iam.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	d, err := tfstate.Parse(raw, accessIAMRoot)
	if err != nil {
		t.Fatal(err)
	}
	return append(fixtureReads(t), Read{Location: accessIAMRoot, Docs: []tfstate.Document{d}})
}

func accessFile(t *testing.T) string {
	t.Helper()
	return filepath.Join("testdata", "access", "who-can.jsonl")
}

func buildAccess(t *testing.T, reads []Read, o Options, files ...string) Result {
	t.Helper()
	o.Access = ReadAccessFiles(files)
	res, err := BuildAll(reads, nil, o)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// accessEdges lists the can_read and can_write edges as "kind/basis/confidence
// from -> to" lines, the nodes by what a person calls them.
func accessEdges(tb snapshot.Tables) []string {
	label := map[string]string{}
	for _, n := range tb.Nodes {
		label[n.NodeID] = first(n.Address, n.InventoryType+n.TFType+":"+n.NativeID)
	}
	var out []string
	for _, e := range tb.Edges {
		if e.Kind == snapshot.EdgeCanRead || e.Kind == snapshot.EdgeCanWrite {
			out = append(out, fmt.Sprintf("%s/%s/%s %s -> %s", e.Kind, e.Basis, e.Confidence, label[e.FromID], label[e.ToID]))
		}
	}
	sort.Strings(out)
	return out
}

func TestAccessEdgesFromIAMLensResults(t *testing.T) {
	res := buildAccess(t, accessReads(t), opts, accessFile(t))
	got := accessEdges(res.Tables)
	// The edges, one by one: the labels of placeholders are their types.
	has := func(line string) bool { return slices.Contains(got, line) }
	for _, line := range []string{
		// An S3 bucket's ARN names no account, so a principal may be of another.
		`can_read/iam_lens_unknown_account/inferred aws_iam_role.app -> aws_s3_bucket.logs["app"]`,
		`can_read/iam_lens_unknown_account/inferred aws_iam_role.app -> aws_s3_bucket.logs["audit"]`,
		`can_read/iam_lens/computed aws_iam_role.app -> aws_db_instance.main`,
		`can_read/iam_lens_unknown_account/inferred aws_iam_role.ci -> aws_s3_bucket.logs["audit"]`,
		`can_write/iam_lens_unknown_account/inferred aws_iam_role.ci -> aws_s3_bucket.logs["app"]`,
		`can_write/iam_lens_unknown_account/inferred aws_iam_user.deploy -> aws_s3_bucket.logs["app"]`,
		`can_read/iam_lens_condition/inferred aws_iam_role.ci -> aws_s3_bucket.logs["app"]`,
		`can_read/iam_lens_public/inferred any_principal:* -> aws_s3_bucket.logs["app"]`,
		`can_write/iam_lens_condition/inferred service_principal:delivery.logs.amazonaws.com -> aws_s3_bucket.logs["app"]`,
		`can_read/iam_lens_unknown_account/inferred aws_iam_role:arn:aws:iam::999999999999:role/partner -> aws_s3_bucket.logs["app"]`,
	} {
		if !has(line) {
			t.Errorf("missing edge %s\nhave:\n%s", line, strings.Join(got, "\n"))
		}
	}
	// 3 + 1 + 2 + 1 + 1 + 1 + 1 + 1: nothing else.
	if len(got) != 10 {
		t.Errorf("%d edges, want 10:\n%s", len(got), strings.Join(got, "\n"))
	}

	// What makes no edge, and says so: a session principal, the sts action, an
	// action of the other level, a resource the snapshot lacks, a wildcard
	// resource, a resource pattern.
	for _, want := range []string{
		"1 iam-lens results are for a resource this snapshot does not hold",
		"1 iam-lens results are for a resource that is not a concrete ARN",
		"2 iam-lens entries are for an action of a level that makes no edge, or an sts action",
		"1 principals of iam-lens results",
		"1 iam-lens results say they found no collected data",
		"1 iam-lens results say they did not check every account",
		"mean only that iam-lens classes an action",
		"does not run iam-lens",
	} {
		if !strings.Contains(res.Limits, want) {
			t.Errorf("limits lack %q:\n%s", want, res.Limits)
		}
	}
	if res.Failed != 0 {
		t.Errorf("failed %d", res.Failed)
	}
}

func TestAccessEdgesEndAtTheSnapshotsNodes(t *testing.T) {
	res := buildAccess(t, accessReads(t), opts, accessFile(t))
	tb := res.Tables
	app := nodeAt(t, tb, accessIAMRoot, "aws_iam_role.app").NodeID
	bucket := nodeAt(t, tb, netRoot, `aws_s3_bucket.logs["app"]`).NodeID
	if !hasEdge(tb, snapshot.EdgeCanRead, BasisIAMLensUnknownAccount, app, bucket) {
		t.Errorf("no can_read from the role to the bucket")
	}
	// The role that the trust policy of another role names is the same node the
	// access edge starts at, not a placeholder of its own.
	n := 0
	for _, node := range tb.Nodes {
		if node.ARNOrPath == "arn:aws:iam::111111111111:role/app" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d nodes for one role", n)
	}
	// The source says what it is and what it holds of.
	var src snapshot.Source
	for _, s := range tb.Sources {
		if s.Kind == snapshot.SourceIAMLens {
			src = s
		}
	}
	if src.Status != snapshot.StatusOK || src.Backend != BackendFile || len(src.DocumentSHA256) != 64 || src.Location != accessFile(t) {
		t.Errorf("source %+v", src)
	}
	if err := snapshot.Validate(&tb); err != nil {
		t.Error(err)
	}
}

func TestAccessKeepsTheStrongestEdgeWhateverTheOrder(t *testing.T) {
	// ci reads logs-app unconditionally in one file and with a condition in
	// another; the unconditional one is kept either way, and the edges do not
	// depend on the order of the files or of the entries.
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	entry := func(extra string) string {
		return `{"principal":"arn:aws:iam::111111111111:role/ci","service":"rds","action":"DescribeDBInstances","level":"list"` + extra + `}`
	}
	doc := func(entries ...string) string {
		return `{"resource":"arn:aws:rds:eu-west-1:111111111111:db:main","result":{"allowed":[` + strings.Join(entries, ",") + `]}}`
	}
	a := write("a.json", doc(entry(`,"conditions":{"conditionType":"condition"}`)))
	b := write("b.json", doc(entry(""), entry(`,"ignoredConditions":{"x":1}`)))
	c := write("c.json", doc(entry(`,"dependsOnSessionName":true`), entry(`,"conditions":{"conditionType":"condition"}`)))

	var first []string
	for i, files := range [][]string{{a, b, c}, {c, b, a}, {b, a}, {a, c}} {
		got := accessEdges(buildAccess(t, accessReads(t), opts, files...).Tables)
		if i == 0 {
			first = got
		}
		wantStrong := slices.Contains(files, b)
		if len(got) != 1 {
			t.Fatalf("%v: %v", files, got)
		}
		if wantStrong && !strings.HasPrefix(got[0], "can_read/iam_lens/computed ") {
			t.Errorf("%v: %v", files, got)
		}
		if !wantStrong && !strings.HasPrefix(got[0], "can_read/iam_lens_condition/inferred ") {
			t.Errorf("%v: %v", files, got)
		}
		if i == 1 && !slices.Equal(got, first) {
			t.Errorf("the order of the files changed the edges: %v vs %v", got, first)
		}
	}
	// The same rows, byte for byte, in two orders.
	one := accessRowsJSON(t, buildAccess(t, accessReads(t), opts, a, b, c))
	two := accessRowsJSON(t, buildAccess(t, accessReads(t), opts, c, a, b))
	if one != two {
		t.Error("the rows depend on the order of the files")
	}
}

// accessRowsJSON is the rows in an order that does not depend on the map the
// builder keeps them in.
func accessRowsJSON(t *testing.T, res Result) string {
	t.Helper()
	tb := res.Tables
	sort.Slice(tb.Nodes, func(i, j int) bool { return tb.Nodes[i].NodeID < tb.Nodes[j].NodeID })
	sort.Slice(tb.Edges, func(i, j int) bool { return tb.Edges[i].EdgeID < tb.Edges[j].EdgeID })
	b, err := json.Marshal(tb)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestAccessResultsHoldNoPolicyTextOrConditionValues(t *testing.T) {
	// The members of an entry the reader does not name (grant details with
	// policy statements, conditions with keys and values) are skipped, and
	// nothing in the rows or the limits holds them.
	const doc = `{"resource":"arn:aws:s3:::acme-logs-app","result":{"allowed":[` +
		`{"principal":"arn:aws:iam::111111111111:role/ci","service":"s3","action":"GetObject","level":"read",` +
		`"conditions":{"conditionType":"condition","key":"PLANTED-COND-KEY","values":["PLANTED-COND-VALUE"]},` +
		`"ignoredConditions":{"identity":{"allow":[{"key":"PLANTED-IGNORED"}]}},` +
		`"details":[{"policyType":"identity","statementId":"PLANTED-SID","policyText":"PLANTED-POLICY-TEXT","arn":"arn:aws:iam::111111111111:policy/PLANTED-POLICY"}]}],` +
		`"principalsNotFound":["arn:aws:iam::777777777777:role/PLANTED-NOT-FOUND"],"PLANTED-EXTRA":"PLANTED-EXTRA-VALUE"}}`
	p := filepath.Join(t.TempDir(), "w.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]Options{"plain": opts, "hashed": hashedOpts(testKey)} {
		res := buildAccess(t, accessReads(t), o, p)
		raw, _ := json.Marshal(res)
		for _, secret := range []string{"PLANTED", "policyText", "statementId", "777777777777"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Errorf("%s: the rows hold %q", name, secret)
			}
		}
		if got := len(accessEdges(res.Tables)); got != 1 {
			t.Errorf("%s: %d edges", name, got)
		}
		if e := accessEdges(res.Tables); !strings.Contains(e[0], "iam_lens_condition/inferred") && name == "plain" {
			t.Errorf("%s: %v", name, e)
		}
	}
}

func TestAccessUnderHashIDs(t *testing.T) {
	plain := buildAccess(t, accessReads(t), opts, accessFile(t))
	hashed := buildAccess(t, accessReads(t), hashedOpts(testKey), accessFile(t))
	if a, b := len(accessEdges(plain.Tables)), len(accessEdges(hashed.Tables)); a != b || a == 0 {
		t.Fatalf("%d edges plain, %d hashed", a, b)
	}
	raw, _ := json.Marshal(hashed)
	for _, leak := range []string{"999999999999", "role/partner", "delivery.logs.amazonaws.com", "acme-logs", "role/ci", "who-can.jsonl"} {
		if bytes.Contains(raw, []byte(leak)) {
			t.Errorf("a hashed snapshot holds %q", leak)
		}
	}
	// The account of the principal from outside the estate is hashed, the same
	// under every node of it; the accounts of the estate stay readable.
	partner := secretscan.Hash(testKey, "999999999999")
	found := false
	for _, n := range hashed.Tables.Nodes {
		if n.Kind == snapshot.KindExternal && n.TFType == "aws_iam_role" && n.Account == partner {
			found = true
		}
	}
	if !found {
		t.Error("the partner's account is not hashed")
	}
	// The same key gives the same edges.
	again := buildAccess(t, accessReads(t), hashedOpts(testKey), accessFile(t))
	if accessRowsJSON(t, hashed) != accessRowsJSON(t, again) {
		t.Error("hashed rows differ between two builds")
	}
}

func TestAccessWithoutAMatchingResourceMakesNoNode(t *testing.T) {
	before := build(t, accessReads(t))
	res := buildAccess(t, accessReads(t), opts, accessFile(t))
	// The only new nodes are the principals no state holds: the partner's role,
	// anyone and the service.
	if got, want := len(res.Tables.Nodes)-len(before.Tables.Nodes), 3; got != want {
		t.Errorf("%d new nodes, want %d", got, want)
	}
	for _, n := range res.Tables.Nodes {
		if strings.Contains(n.NativeID+n.ARNOrPath, "not-in-the-snapshot") {
			t.Errorf("a node for a resource the snapshot lacks: %+v", n)
		}
	}
}

func TestAccessFileThatFailsDoesNotStopTheRest(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"simulationCount":1,"allowed":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, o := range map[string]Options{"plain": opts, "hashed": hashedOpts(testKey)} {
		res := buildAccess(t, accessReads(t), o, bad, accessFile(t), filepath.Join(dir, "missing.json"))
		if res.Failed != 2 {
			t.Errorf("%s: failed %d, want 2", name, res.Failed)
		}
		if len(accessEdges(res.Tables)) == 0 {
			t.Errorf("%s: no edge from the file that read", name)
		}
		var failed []snapshot.Source
		for _, s := range res.Tables.Sources {
			if s.Kind == snapshot.SourceIAMLens && s.Status == snapshot.StatusFailed {
				failed = append(failed, s)
			}
		}
		if len(failed) != 2 {
			t.Fatalf("%s: %d failed sources", name, len(failed))
		}
		for _, s := range failed {
			if name == "plain" && !strings.Contains(s.Reason, "wrap each who-can output") && !strings.Contains(s.Reason, "no such file") {
				t.Errorf("reason %q", s.Reason)
			}
			if name == "hashed" && s.Reason != withheld {
				t.Errorf("reason %q", s.Reason)
			}
		}
		if !strings.Contains(res.Limits, "2 iam-lens files could not be read") {
			t.Errorf("%s: limits: %s", name, res.Limits)
		}
	}
}

func TestParseAccessShapes(t *testing.T) {
	const one = `{"resource":"arn:aws:s3:::b","result":{"allowed":[{"principal":"p","service":"s3","action":"GetObject","level":"read"}]}}`
	for _, tc := range []struct {
		name, in, err string
		results       int
	}{
		{"one object", one, "", 1},
		{"an array", "[" + one + "," + one + "]", "", 2},
		{"json lines", one + "\n" + one + "\n" + one, "", 3},
		{"no results", "", "no results", 0},
		{"not json", "{not", "not JSON", 0},
		{"raw who-can output", `{"simulationCount":0,"allowed":[]}`, "wrap each who-can output", 0},
		{"no allowed", `{"resource":"arn:aws:s3:::b","result":{}}`, "wrap each who-can output", 0},
		{"null allowed", `{"resource":"arn:aws:s3:::b","result":{"allowed":null}}`, "wrap each who-can output", 0},
		{"no principal", `{"resource":"r","result":{"allowed":[{"level":"read"}]}}`, "a principal and a level are required", 0},
		{"no level", `{"resource":"r","result":{"allowed":[{"principal":"p"}]}}`, "a principal and a level are required", 0},
		{"empty principal", `{"resource":"r","result":{"allowed":[{"principal":"","level":"read"}]}}`, "a principal and a level are required", 0},
		{"a number for a principal", `{"resource":"r","result":{"allowed":[{"principal":5,"level":"read"}]}}`, "not JSON of the expected shape", 0},
		{"a string for a result", `{"resource":"r","result":"x"}`, "not JSON of the expected shape", 0},
		{"a number", `7`, "not JSON of the expected shape", 0},
		{"an array then objects", "[" + one + "]\n" + one + "\n[" + one + "," + one + "]", "", 4},
		{"an empty array", `[]`, "no results", 0},
		{"an unclosed array", "[" + one, "not JSON", 0},
		{"allowed that is not a list", `{"resource":"r","result":{"allowed":{}}}`, "is not a list", 0},
		{"trailing text", one + " trailing", "not JSON", 0},
		{"no entries is fine", `{"resource":"r","result":{"allowed":[]}}`, "", 1},
	} {
		doc, err := ParseAccess([]byte(tc.in))
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%s: %v", tc.name, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%s: error %v, want %q", tc.name, err, tc.err)
		case err == nil && len(doc.Results) != tc.results:
			t.Errorf("%s: %d results", tc.name, len(doc.Results))
		}
		if err != nil && strings.Contains(err.Error(), "PLANTED") {
			t.Errorf("%s: the error quotes the input", tc.name)
		}
	}
}

func TestParseAccessCaps(t *testing.T) {
	var sb strings.Builder
	for i := 0; i <= maxAccessResults; i++ {
		sb.WriteString(`{"resource":"arn:aws:s3:::b","result":{"allowed":[]}}` + "\n")
	}
	if _, err := ParseAccess([]byte(sb.String())); err == nil || !strings.Contains(err.Error(), "more than 10000 results") {
		t.Errorf("results cap: %v", err)
	}

	// The same in an array, which is read an item at a time.
	arr := "[" + strings.TrimSuffix(strings.ReplaceAll(sb.String(), "\n", ","), ",") + "]"
	if _, err := ParseAccess([]byte(arr)); err == nil || !strings.Contains(err.Error(), "more than 10000 results") {
		t.Errorf("results cap in an array: %v", err)
	}

	sb.Reset()
	sb.WriteString(`{"resource":"arn:aws:s3:::b","result":{"allowed":[`)
	for i := 0; i <= maxAccessEntries; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"principal":"p","service":"s3","action":"a","level":"read"}`)
	}
	sb.WriteString(`]}}`)
	if _, err := ParseAccess([]byte(sb.String())); err == nil || !strings.Contains(err.Error(), "more than 200000 entries") {
		t.Errorf("entries cap: %v", err)
	}

	big := filepath.Join(t.TempDir(), "big.json")
	f, err := os.Create(big)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxAccessBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if _, err := ReadAccess(big); err == nil || !strings.Contains(err.Error(), "larger than 32 MiB") {
		t.Errorf("size cap: %v", err)
	}
}

// manyBuckets is a state of n buckets.
func manyBuckets(t *testing.T, n int) []Read {
	t.Helper()
	var rs []string
	for i := 0; i < n; i++ {
		rs = append(rs, fmt.Sprintf(`{"mode":"managed","type":"aws_s3_bucket","name":"b%d","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
		 "instances":[{"attributes":{"id":"bucket-%d","arn":"arn:aws:s3:::bucket-%d"}}]}`, i, i, i))
	}
	state := `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[` + strings.Join(rs, ",") + `]}`
	d, err := tfstate.Parse([]byte(state), "s3://acme/buckets.tfstate")
	if err != nil {
		t.Fatal(err)
	}
	return []Read{{Location: "s3://acme/buckets.tfstate", Docs: []tfstate.Document{d}}}
}

// accessCapFile writes a file of buckets that each list principals with the
// numbers of principals given, and returns its path.
func accessCapFile(t *testing.T, buckets, principals int) string {
	t.Helper()
	var sb strings.Builder
	for b := 0; b < buckets; b++ {
		fmt.Fprintf(&sb, `{"resource":"arn:aws:s3:::bucket-%d","result":{"allowed":[`, b)
		for q := 0; q < principals; q++ {
			if q > 0 {
				sb.WriteByte(',')
			}
			fmt.Fprintf(&sb, `{"principal":"arn:aws:iam::222222222222:role/r%05d","service":"s3","action":"GetObject","level":"read"}`, q)
		}
		sb.WriteString("]}}\n")
	}
	p := filepath.Join(t.TempDir(), "many.jsonl")
	if err := os.WriteFile(p, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAccessEdgeCap(t *testing.T) {
	// 11 buckets read by 10,000 principals each are 110,000 edges: the first
	// 100,000 in the order of the principals are written, and the rest counted.
	file := accessCapFile(t, 11, maxAccessPrincipals)
	res := buildAccess(t, manyBuckets(t, 11), opts, file)
	if got := len(accessEdges(res.Tables)); got != maxAccessEdges {
		t.Errorf("%d edges, want %d", got, maxAccessEdges)
	}
	if !strings.Contains(res.Limits, "caps of 100000 can_read and can_write edges and 10000 principals were reached: 10000 edges are left out") {
		t.Errorf("limits: %s", res.Limits)
	}
	// Which edges are left out does not depend on the map's order.
	again := buildAccess(t, manyBuckets(t, 11), opts, file)
	if accessRowsJSON(t, res) != accessRowsJSON(t, again) {
		t.Error("the rows that survive the cap differ between two builds")
	}
}

func TestAccessPrincipalCap(t *testing.T) {
	res := buildAccess(t, manyBuckets(t, 1), opts, accessCapFile(t, 1, maxAccessPrincipals+1))
	if got := len(accessEdges(res.Tables)); got != maxAccessPrincipals {
		t.Errorf("%d edges, want %d", got, maxAccessPrincipals)
	}
	placeholders := 0
	for _, n := range res.Tables.Nodes {
		if n.Kind == snapshot.KindExternal {
			placeholders++
		}
	}
	if placeholders != maxAccessPrincipals {
		t.Errorf("%d placeholders, want %d", placeholders, maxAccessPrincipals)
	}
	if !strings.Contains(res.Limits, "1 edges are left out") {
		t.Errorf("limits: %s", res.Limits)
	}
}

func TestAccessKind(t *testing.T) {
	for _, tc := range []struct{ service, level, want string }{
		{"s3", "read", snapshot.EdgeCanRead},
		{"s3", "List", snapshot.EdgeCanRead},
		{"s3", "write", snapshot.EdgeCanWrite},
		{"s3", "tagging", snapshot.EdgeCanWrite},
		{"iam", "permissions management", snapshot.EdgeCanWrite},
		{"s3", "other", ""},
		{"s3", "", ""},
		{"sts", "write", ""},
		{"STS", "read", ""},
	} {
		if got := accessKind(tc.service, tc.level); got != tc.want {
			t.Errorf("%s %s: %q, want %q", tc.service, tc.level, got, tc.want)
		}
	}
}

func TestValidARN(t *testing.T) {
	for arn, want := range map[string]bool{
		"arn:aws:s3:::bucket":                        true,
		"arn:aws:rds:eu-west-1:111111111111:db:main": true,
		"arn:aws:s3:::bucket/*":                      false,
		"arn:aws:s3:::b?cket":                        false,
		"arn:aws:s3":                                 false,
		"bucket":                                     false,
		"arn:aws:s3:::bu\x00cket":                    false,
		"arn:aws:s3:::" + strings.Repeat("a", 2100):  false,
	} {
		if got := validARN(arn); got != want {
			t.Errorf("%q: %v", arn, got)
		}
	}
}

func TestAccessPrincipals(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want tfstate.TrustPrincipal
	}{
		{"anonymous", tfstate.TrustPrincipal{Type: "*", Value: "*"}},
		{"arn:aws:iam::111111111111:role/x", tfstate.TrustPrincipal{Type: "AWS", Value: "arn:aws:iam::111111111111:role/x"}},
		{"lambda.amazonaws.com", tfstate.TrustPrincipal{Type: "Service", Value: "lambda.amazonaws.com"}},
		{"arn:aws:iam::111111111111:role/*", tfstate.TrustPrincipal{Type: "*", Value: "arn:aws:iam::111111111111:role/*"}},
		{"not a principal", tfstate.TrustPrincipal{Type: "*", Value: "not a principal"}},
		{"arn:aws:iam::111111111111:role/x\x1b[31m", tfstate.TrustPrincipal{Type: "*", Value: "rejected"}},
		{"arn:aws:iam::111111111111:role/" + strings.Repeat("a", 3000), tfstate.TrustPrincipal{Type: "*", Value: "rejected"}},
	} {
		if got := accessPrincipal(tc.in); got != tc.want {
			t.Errorf("%s: %+v", tc.in, got)
		}
	}
}

// TestAccessGolden pins the rows of the fixture states joined to the iam-lens
// fixture in a form a person can review, and the bytes of the snapshot through
// the hashes in its manifest.
func TestAccessGolden(t *testing.T) {
	res := buildAccess(t, accessReads(t), opts, accessFile(t))
	got := map[string][]byte{
		"access-manifest.json": writeFilesWith(t, res)["manifest.json"],
		"access-graph.txt":     []byte(render(res.Tables)),
	}
	dir := filepath.Join("testdata", "golden")
	for name, data := range got {
		path := filepath.Join(dir, name)
		if *update {
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%v (run go test ./internal/ingest -update)", err)
		}
		if !bytes.Equal(data, want) {
			t.Errorf("%s differs from the golden file (run go test ./internal/ingest -update and review the diff)", name)
		}
	}
	var m snapshot.Manifest
	if err := json.Unmarshal(got["access-manifest.json"], &m); err != nil || m.Status != snapshot.StatusOK ||
		m.SourcesSummary.ByKind[snapshot.SourceIAMLens] != 1 || m.FormatMinor != 3 {
		t.Errorf("manifest: %v %+v", err, m)
	}
}

// FuzzParseAccess feeds the reader of iam-lens files bytes that are not what
// iam-lens printed: it must not panic, whatever it holds, and what it keeps
// must be within the caps.
func FuzzParseAccess(f *testing.F) {
	raw, err := os.ReadFile(filepath.Join("testdata", "access", "who-can.jsonl"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`[{"resource":"arn:aws:s3:::b","result":{"allowed":[{"principal":"p","level":"read","conditions":null}]}}]`))
	f.Add([]byte(`{"resource":"r","result":{"allowed":[{"principal":"p","level":"read","allowedPatterns":[{}],"dependsOnSessionName":"x"}]}}`))
	f.Fuzz(func(t *testing.T, in []byte) {
		doc, err := ParseAccess(in)
		if err != nil {
			return
		}
		entries := 0
		for _, r := range doc.Results {
			entries += len(r.Entries)
		}
		if len(doc.Results) > maxAccessResults || entries > maxAccessEntries || len(doc.Digest) != 64 {
			t.Errorf("%d results, %d entries, digest %q", len(doc.Results), entries, doc.Digest)
		}
	})
}

// accessDoc is a file of one result for the fixture's database (accessDB), with the
// entries given: principal, level and extra members of each.
func accessDoc(t *testing.T, entries ...[3]string) string {
	t.Helper()
	var es []string
	for _, e := range entries {
		es = append(es, fmt.Sprintf(`{"principal":%q,"service":"rds","action":"DescribeDBInstances","level":%q%s}`, e[0], e[1], e[2]))
	}
	p := filepath.Join(t.TempDir(), "doc.json")
	body := fmt.Sprintf(`{"resource":%q,"result":{"allowed":[%s]}}`, accessDB, strings.Join(es, ","))
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const accessDB = "arn:aws:rds:eu-west-1:111111111111:db:main"

func TestAccessBasisFollowsThePrincipal(t *testing.T) {
	cond := `,"conditions":{"conditionType":"condition"}`
	file := accessDoc(t,
		[3]string{"arn:aws:iam::111111111111:role/app", "read", ""},       // same account
		[3]string{"arn:aws:iam::999999999999:role/partner", "read", ""},   // another account
		[3]string{"arn:aws:iam::111111111111:root", "read", ""},           // an account
		[3]string{"arn:aws:iam::111111111111:user/deploy", "write", cond}, // conditional, same account
		[3]string{"anonymous", "write", cond},                             // public with a condition
		[3]string{"*", "read", ""}, [3]string{"anonymous", "read", cond},  // one edge: the unconditional
	)
	got := accessEdges(buildAccess(t, accessReads(t), opts, file).Tables)
	want := []string{
		`can_read/iam_lens/computed aws_iam_role.app -> aws_db_instance.main`,
		`can_read/iam_lens_cross_account/inferred aws_iam_role:arn:aws:iam::999999999999:role/partner -> aws_db_instance.main`,
		`can_read/iam_lens_account/inferred :arn:aws:iam::111111111111:root -> aws_db_instance.main`,
		`can_write/iam_lens_condition/inferred aws_iam_user.deploy -> aws_db_instance.main`,
		`can_write/iam_lens_public_condition/inferred any_principal:* -> aws_db_instance.main`,
		`can_read/iam_lens_public/inferred any_principal:* -> aws_db_instance.main`,
	}
	// The account node is labelled by what it is, whatever its label is.
	n := 0
	for _, line := range got {
		if strings.HasPrefix(line, "can_read/iam_lens_account/inferred ") {
			n++
			continue
		}
		if !slices.Contains(want, line) {
			t.Errorf("unexpected edge %s", line)
		}
	}
	if n != 1 {
		t.Errorf("%d account edges:\n%s", n, strings.Join(got, "\n"))
	}
	for _, line := range want {
		if !strings.HasPrefix(line, "can_read/iam_lens_account") && !slices.Contains(got, line) {
			t.Errorf("missing edge %s\nhave:\n%s", line, strings.Join(got, "\n"))
		}
	}
	// "*" and anonymous are one principal, so the unconditional read of "*"
	// and the conditional read of anonymous are one edge, the unconditional
	// kept, and the conditional write of anonymous keeps its own basis.
	if len(got) != len(want) {
		t.Errorf("%d edges, want %d:\n%s", len(got), len(want), strings.Join(got, "\n"))
	}
}

func TestAccessStarIsPublicLikeAnonymous(t *testing.T) {
	// "*" alone must not outrank anonymous as computed: it is inferred, with
	// the same basis.
	for _, p := range []string{"*", "anonymous"} {
		got := accessEdges(buildAccess(t, accessReads(t), opts, accessDoc(t, [3]string{p, "read", ""})).Tables)
		if len(got) != 1 || got[0] != `can_read/iam_lens_public/inferred any_principal:* -> aws_db_instance.main` {
			t.Errorf("%s: %v", p, got)
		}
	}
}

func TestParseAccessDigestIgnoresTheOrder(t *testing.T) {
	r := func(resource string, level string, extra string) string {
		return fmt.Sprintf(`{"resource":%q,"result":{"allowed":[{"principal":"p","service":"s3","action":"a","level":%q}]%s}}`, resource, level, extra)
	}
	// The same resource twice with different content, and another resource.
	a, b, c := r("arn:aws:s3:::x", "read", ""), r("arn:aws:s3:::x", "write", ""), r("arn:aws:s3:::y", "read", `,"allAccountsChecked":false`)
	var digests []string
	for _, order := range [][]string{{a, b, c}, {c, b, a}, {b, a, c}, {b, c, a}} {
		doc, err := ParseAccess([]byte(strings.Join(order, "\n")))
		if err != nil {
			t.Fatal(err)
		}
		digests = append(digests, doc.Digest)
		arr, err := ParseAccess([]byte("[" + strings.Join(order, ",") + "]"))
		if err != nil || arr.Digest != doc.Digest {
			t.Errorf("an array of the same results: %v", err)
		}
	}
	for _, d := range digests {
		if d != digests[0] {
			t.Errorf("the digest depends on the order: %v", digests)
		}
	}
	// And it does depend on what is held, including a scoped run.
	other, err := ParseAccess([]byte(strings.Join([]string{a, b, r("arn:aws:s3:::y", "read", "")}, "\n")))
	if err != nil || other.Digest == digests[0] {
		t.Errorf("a scoped result and a complete one have one digest: %v", err)
	}
}

func TestAccessCountsDuplicateLocationsAndScopedRuns(t *testing.T) {
	file := accessDoc(t, [3]string{"arn:aws:iam::111111111111:role/app", "read", ""})
	res := buildAccess(t, accessReads(t), opts, file, file, filepath.Join(filepath.Dir(file), ".", filepath.Base(file)))
	if got := len(accessEdges(res.Tables)); got != 1 {
		t.Errorf("%d edges", got)
	}
	if !strings.Contains(res.Limits, "2 iam-lens locations were given more than once and were read once") {
		t.Errorf("limits: %s", res.Limits)
	}
	if res.Failed != 0 {
		t.Errorf("failed %d", res.Failed)
	}
	sources := 0
	for _, s := range res.Tables.Sources {
		if s.Kind == snapshot.SourceIAMLens {
			sources++
		}
	}
	if sources != 1 {
		t.Errorf("%d sources for one file", sources)
	}
	// The fixture's first result is of a run that did not check every account.
	res = buildAccess(t, accessReads(t), opts, accessFile(t))
	if !strings.Contains(res.Limits, "1 iam-lens results say they did not check every account (allAccountsChecked is false") {
		t.Errorf("limits: %s", res.Limits)
	}
}

func TestAccessOfAHashedInventoryIsReportedNotCountedAsAbsent(t *testing.T) {
	h := func(s string) string { return secretscan.Hash(testKey, s) }
	inv := Inventory{
		Location: "hashed.inventory.json", Schema: SchemaInventory, Tool: "infraharvest", IDsHashed: true,
		Resources: []Resource{{Cloud: "aws", Account: "111111111111", Region: "eu-west-1", Type: "aws_db_instance", ID: h("main"), CloudID: h(accessDB), Status: "unmanaged", Basis: "none"}},
	}
	inv.Digest = digestOf(inv)
	o := opts
	o.HashKey = testKey
	o.Access = ReadAccessFiles([]string{accessDoc(t, [3]string{"arn:aws:iam::111111111111:role/app", "read", ""})})
	res, err := BuildAll(nil, []InventoryRead{{Location: inv.Location, Inv: inv}}, o)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(accessEdges(res.Tables)); got != 0 {
		t.Errorf("%d edges", got)
	}
	for _, want := range []string{
		"1 AWS resources of an inventory written with --hash-ids have an ARN that is a hash",
		"1 iam-lens results are for a resource this snapshot does not hold",
	} {
		if !strings.Contains(res.Limits, want) {
			t.Errorf("limits lack %q:\n%s", want, res.Limits)
		}
	}
}

func TestAccessTotalCapsAcrossFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, entries int) string {
		var es []string
		for i := 0; i < entries; i++ {
			es = append(es, `{"principal":"p","service":"s3","action":"a","level":"read"}`)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(`{"resource":"arn:aws:s3:::b","result":{"allowed":[`+strings.Join(es, ",")+`]}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a, b, c := write("a.json", 6), write("b.json", 6), write("c.json", 2)
	// 10 entries in all: a (6) is read, b (6) is past the cap, c (2) is read.
	// The order of the arguments does not change which.
	for _, files := range [][]string{{a, b, c}, {c, b, a}, {b, c, a}} {
		reads := readAccessFiles(files, 1<<20, 10)
		var failed []string
		for _, r := range reads {
			if r.Err != nil {
				failed = append(failed, filepath.Base(r.Location))
				if !strings.Contains(r.Err.Error(), "total of 10 entries") {
					t.Errorf("reason %q", r.Err)
				}
			}
		}
		if !slices.Equal(failed, []string{"b.json"}) {
			t.Errorf("%v: failed %v", files, failed)
		}
	}
	// Bytes: the files in the order of their locations take the budget.
	info, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	budget := int(info.Size()) + 10
	for _, files := range [][]string{{a, b, c}, {c, b, a}} {
		reads := readAccessFiles(files, budget, 1000)
		for _, r := range reads {
			base := filepath.Base(r.Location)
			if (base == "a.json") != (r.Err == nil) {
				t.Errorf("%v: %s: %v", files, base, r.Err)
			}
			if r.Err != nil && !strings.Contains(r.Err.Error(), "total of 128 MiB") {
				t.Errorf("reason %q", r.Err)
			}
		}
	}
}
