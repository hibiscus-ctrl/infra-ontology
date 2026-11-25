// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// update rewrites the golden files: go test ./internal/snapshot -update. Review
// the diff before committing; the Parquet bytes change when the library does.
var update = flag.Bool("update", false, "rewrite the golden files")

var fixedTime = time.Date(2026, 11, 25, 10, 15, 0, 0, time.UTC)

// A small estate: two environments in two accounts, each with a state root, a
// module, a VPC, a subnet and an instance, a bucket that only prod's state
// has, one bucket found in prod's account that no state holds, and staging
// reading prod's state (and one outside the snapshot) through remote state.
type estateBuilder struct {
	t      Tables
	byAddr map[string]string
}

func (b *estateBuilder) node(n Node) {
	if n.NodeID == "" {
		typ := n.TFType
		if typ == "" {
			typ = n.InventoryType
		}
		n.NodeID = NodeID(n.Kind, n.Cloud, n.Account, n.Region, typ, n.NativeID)
	}
	if b.byAddr == nil {
		b.byAddr = map[string]string{}
	}
	b.byAddr[first(n.Address, n.Name, n.NativeID)] = n.NodeID
	b.t.Nodes = append(b.t.Nodes, n)
}

func (b *estateBuilder) edge(kind, from, to, basis, conf, source string) {
	b.t.Edges = append(b.t.Edges, Edge{
		FromID: b.byAddr[from], ToID: b.byAddr[to], Kind: kind, Basis: basis, Confidence: conf, SourceID: source,
	})
}

func first(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func estate() Tables {
	var b estateBuilder
	serial := func(n int64) *int64 { return &n }
	b.t.Sources = []Source{
		{SourceID: "state-prod", Kind: SourceState, Backend: "s3", Location: "s3://acme-tfstate/prod/net.tfstate", Workspace: "default",
			Serial: serial(42), Lineage: "5c1f0a3e-0d2b-4b8e-9f47-0a1b2c3d4e5f", TerraformVersion: "1.9.8",
			DocumentSHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
			CollectedAt:    "2026-11-25T09:58:00Z", Collector: "infra-ontology", CollectorVersion: "dev", Status: StatusOK},
		{SourceID: "state-staging", Kind: SourceState, Backend: "s3", Location: "s3://acme-tfstate/staging/net.tfstate", Workspace: "default",
			Serial: serial(17), Lineage: "7a2e9b1c-3f4d-4c5a-8b6e-1d2c3b4a5f60", TerraformVersion: "1.9.8",
			DocumentSHA256: "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752",
			CollectedAt:    "2026-11-25T09:59:00Z", Collector: "infra-ontology", CollectorVersion: "dev", Status: StatusOK},
		{SourceID: "inventory-aws", Kind: SourceInventory, Backend: "file", Location: "inventory.json",
			DocumentSHA256: "fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13",
			CollectedAt:    "2026-11-25T10:05:00+01:00", Collector: "infraharvest", CollectorVersion: "0.1.0", Status: StatusOK},
	}

	envs := []struct{ env, account, source string }{
		{"prod", "111111111111", "state-prod"},
		{"staging", "222222222222", "state-staging"},
	}
	for _, e := range envs {
		tags := map[string]string{"environment": e.env, "owner": "platform"}
		b.node(Node{Kind: KindAccount, Cloud: "aws", Account: e.account, Name: e.env + "-account", NativeID: e.account,
			ManagedStatus: Unknown, Environment: e.env, Confidence: Observed, SourceID: e.source})
		b.node(Node{Kind: KindStateRoot, Name: e.env + "-net", NativeID: "net/" + e.env, Root: "net/" + e.env,
			ManagedStatus: Managed, Environment: e.env, Confidence: Observed, SourceID: e.source})
		b.node(Node{Kind: KindModuleCall, Name: "network", Address: "module.network", Root: "net/" + e.env,
			NativeID: e.env + "/module.network", ManagedStatus: Managed, Environment: e.env, Confidence: Observed, SourceID: e.source})
		res := func(typ, addr, native, module string) {
			b.node(Node{Kind: KindResource, Cloud: "aws", Account: e.account, Region: "eu-west-1", TFType: typ,
				InventoryType: "AWS::EC2::" + typ, NativeID: native, ARNOrPath: "arn:aws:ec2:eu-west-1:" + e.account + ":" + native,
				Name: native, Address: addr, Module: module, Root: "net/" + e.env, ManagedStatus: Managed,
				Environment: e.env, Tags: tags, Confidence: Observed, SourceID: e.source})
		}
		res("aws_vpc", "module.network.aws_vpc.main", e.env+"-vpc-0a1b", "module.network")
		res("aws_subnet", "module.network.aws_subnet.private", e.env+"-subnet-0c2d", "module.network")
		res("aws_instance", "aws_instance.app", e.env+"-i-0e3f", "")

		b.edge(EdgeDependsOn, "module.network.aws_subnet.private", "module.network.aws_vpc.main", "state_dependency", Observed, e.source)
		b.edge(EdgeDependsOn, "aws_instance.app", "module.network.aws_subnet.private", "state_dependency", Observed, e.source)
		b.edge(EdgeContainedIn, "module.network.aws_vpc.main", "module.network", "module_containment", Computed, e.source)
		b.edge(EdgeContainedIn, "module.network.aws_subnet.private", "module.network", "module_containment", Computed, e.source)
		b.edge(EdgeContainedIn, "module.network", e.env+"-net", "module_containment", Computed, e.source)
		b.edge(EdgeDefinedIn, "aws_instance.app", e.env+"-net", "state_membership", Observed, e.source)
		if e.env == "prod" {
			b.node(Node{Kind: KindResource, Cloud: "aws", Account: e.account, Region: "eu-west-1", TFType: "aws_s3_bucket",
				InventoryType: "AWS::S3::Bucket", NativeID: "acme-prod-logs", ARNOrPath: "arn:aws:s3:::acme-prod-logs",
				Name: "acme-prod-logs", Address: "aws_s3_bucket.logs", Root: "net/prod", ManagedStatus: Managed,
				Environment: "prod", Tags: tags, Confidence: Observed, SourceID: e.source})
			b.node(Node{Kind: KindResource, Cloud: "aws", Account: e.account, Region: "eu-west-1", TFType: "aws_s3_bucket",
				InventoryType: "AWS::S3::Bucket", NativeID: "acme-legacy-uploads", ARNOrPath: "arn:aws:s3:::acme-legacy-uploads",
				Name: "acme-legacy-uploads", ManagedStatus: Unmanaged, Environment: "prod", Confidence: Observed, SourceID: "inventory-aws"})
			b.edge(EdgeContainedIn, "acme-legacy-uploads", "prod-account", "resource_path", Observed, "inventory-aws")
		}
	}
	// Staging reads prod's state, and one that is not in the snapshot.
	b.node(Node{Kind: KindExternal, Name: "s3://acme-other/shared.tfstate", NativeID: "s3://acme-other/shared.tfstate",
		ManagedStatus: Unknown, Confidence: Inferred, SourceID: "state-staging"})
	b.edge(EdgeReadsStateOf, "staging-net", "prod-net", "remote_state", Observed, "state-staging")
	b.edge(EdgeReadsStateOf, "staging-net", "s3://acme-other/shared.tfstate", "remote_state", Observed, "state-staging")
	return b.t
}

func estateOptions() BuildOptions {
	return BuildOptions{
		CreatedAt: fixedTime,
		Label:     "baseline",
		Tool:      Tool{Name: "infra-ontology", Version: "dev"},
		Redaction: Redaction{HashAlgorithm: "none", TagKeysDropped: []string{"password", "api_key"}},
		Limits:    "A fixture: not read from a real estate.",
	}
}

// writeEstateJSON writes the `snapshot build --from-json` form of the estate.
func writeEstateJSON(t *testing.T, path string) {
	t.Helper()
	opts := estateOptions()
	doc := map[string]any{
		"created_at": opts.CreatedAt.Format(time.RFC3339),
		"label":      opts.Label,
		"limits":     opts.Limits,
		"redaction":  opts.Redaction,
	}
	tables := estate()
	doc["nodes"], doc["edges"], doc["sources"] = tables.Nodes, tables.Edges, tables.Sources
	// Edge ids are filled by the writer; leave them out of the fixture.
	for i := range tables.Edges {
		tables.Edges[i].EdgeID = ""
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.ReplaceAll(raw, []byte("      \"edge_id\": \"\",\n"), nil)
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func goldenDir() string { return filepath.Join("testdata", "golden", "estate") }
