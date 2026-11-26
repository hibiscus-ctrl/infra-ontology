// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"bytes"
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/secretscan"
	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

const tagsRoot = "s3://acme-tfstate/prod/tags.tfstate"

// tagState is a state with one resource of each cloud, each with its tags or
// labels as the provider writes them. The AWS instance has tags_all, which
// wins where the two differ.
func tagState(extra string) string {
	return `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[
	 {"mode":"managed","type":"aws_instance","name":"web","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"i-0f00aa11","arn":"arn:aws:ec2:eu-west-1:111111111111:instance/i-0f00aa11",
	   "tags":{"env":"dev","team":"web"},"tags_all":{"env":"prod","team":"web","cost-centre":"42"}}}]},
	 {"mode":"managed","type":"azurerm_resource_group","name":"rg","provider":"provider[\"registry.terraform.io/hashicorp/azurerm\"]",
	  "instances":[{"attributes":{"id":"/subscriptions/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourceGroups/rg-app",
	   "tags":{"env":"stage","owner":"platform"}}}]},
	 {"mode":"managed","type":"google_storage_bucket","name":"b","provider":"provider[\"registry.terraform.io/hashicorp/google\"]",
	  "instances":[{"attributes":{"id":"projects/acme-prod/buckets/acme-bucket","labels":{"env":"dev","team":"data"}}}]},
	 {"mode":"managed","type":"aws_sqs_queue","name":"q","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"https://sqs.eu-west-1.amazonaws.com/111111111111/jobs"}}]}` + extra + `]}`
}

func tagReads(t *testing.T, extra string) []Read {
	t.Helper()
	d, err := tfstate.Parse([]byte(tagState(extra)), tagsRoot)
	if err != nil {
		t.Fatal(err)
	}
	return []Read{{Location: tagsRoot, Docs: []tfstate.Document{d}}}
}

func nodeByAddress(t *testing.T, tb snapshot.Tables, address string) snapshot.Node {
	t.Helper()
	return nodeAt(t, tb, tagsRoot, address)
}

func TestStateTagsAndLabelsReachTheNodes(t *testing.T) {
	tb := build(t, tagReads(t, "")).Tables
	for address, want := range map[string]map[string]string{
		// tags_all wins over tags where they differ, and adds the provider's default tags.
		"aws_instance.web":          {"env": "prod", "team": "web", "cost-centre": "42"},
		"azurerm_resource_group.rg": {"env": "stage", "owner": "platform"},
		"google_storage_bucket.b":   {"env": "dev", "team": "data"},
		"aws_sqs_queue.q":           nil,
	} {
		if got := nodeByAddress(t, tb, address).Tags; !maps.Equal(got, want) {
			t.Errorf("%s: tags %v, want %v", address, got, want)
		}
	}
}

func TestStateTagsPassTheTagFilter(t *testing.T) {
	// A credential-shaped value and a secret-named key go, whatever the
	// other tags are. The values are put together here so that no file of
	// the repository holds one.
	awsKey := "wJalrXUtnFEMI/K7MDENG/bPx" + "RfiCYEXAMPLEKEY"
	extra := `,{"mode":"managed","type":"aws_s3_bucket","name":"logs","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"acme-logs-app","tags":{"env":"dev","note":"` + awsKey + `","memo":"pass` + `word=PLANTED-TAG-VALUE","db_password":"PLANTED-TAG-KEY","Name":"acme-logs-app"}}}]}`

	res := build(t, tagReads(t, extra))
	n := nodeByAddress(t, res.Tables, "aws_s3_bucket.logs")
	if want := map[string]string{"env": "dev", "Name": "acme-logs-app"}; !maps.Equal(n.Tags, want) {
		t.Errorf("tags %v, want %v", n.Tags, want)
	}
	if want := []string{"db_password", "memo", "note"}; !slices.Equal(res.Redaction.TagKeysDropped, want) {
		t.Errorf("tag keys dropped %v, want %v", res.Redaction.TagKeysDropped, want)
	}
	if !strings.Contains(res.Limits, "3 tags look like secrets") {
		t.Errorf("limits: %s", res.Limits)
	}
	raw, _ := json.Marshal(res)
	for _, secret := range []string{awsKey, "PLANTED-TAG"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the planted %q is in the result", secret)
		}
	}

	// --drop-tag and --drop-tags.
	o := opts
	o.DropTags = []string{"team"}
	r2, err := Build(tagReads(t, extra), o)
	if err != nil {
		t.Fatal(err)
	}
	if got := nodeByAddress(t, r2.Tables, "aws_instance.web").Tags; !maps.Equal(got, map[string]string{"env": "prod", "cost-centre": "42"}) {
		t.Errorf("tags with team dropped: %v", got)
	}
	o = opts
	o.DropAllTags = true
	r3, err := Build(tagReads(t, extra), o)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range r3.Tables.Nodes {
		if len(n.Tags) > 0 {
			t.Errorf("%s keeps tags with --drop-tags: %v", n.Address, n.Tags)
		}
	}
	if !r3.Redaction.AllTagsDropped {
		t.Errorf("redaction: %+v", r3.Redaction)
	}
}

func TestStateTagsAreHashedWithTheIDs(t *testing.T) {
	// A Name tag, a tag that holds the ID and a tag whose key names the
	// resource give away what --hash-ids hides, so they are hashed or dropped.
	extra := `,{"mode":"managed","type":"aws_s3_bucket","name":"logs","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"acme-logs-app","tags":{"env":"dev","Name":"web-frontend-7","arn":"arn:aws:s3:::acme-logs-app","kubernetes.io/cluster/acme-logs-app":"owned"}}}]},
	 {"mode":"managed","type":"aws_sqs_queue","name":"jobs","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"https://sqs.eu-west-1.amazonaws.com/111111111111/jobs-prod","arn":"arn:aws:sqs:eu-west-1:111111111111:jobs-prod",
	   "tags":{"queue_arn":"arn:aws:sqs:eu-west-1:111111111111:jobs-prod","env":"dev"}}}]}`
	o := opts
	o.HashKey = []byte("tags-test-key-0123456789")
	res, err := Build(tagReads(t, extra), o)
	if err != nil {
		t.Fatal(err)
	}
	var n snapshot.Node
	for _, c := range res.Tables.Nodes {
		if c.TFType == "aws_s3_bucket" {
			n = c
		}
	}
	if len(n.Tags) != 3 || n.Tags["env"] != "dev" {
		t.Fatalf("tags %v", n.Tags)
	}
	for _, k := range []string{"Name", "arn"} {
		if v := n.Tags[k]; v == "" || v == "web-frontend-7" || strings.Contains(v, "acme-logs-app") {
			t.Errorf("tag %s is %q, want a hash", k, v)
		}
	}
	// The queue's ID is its URL, so its ARN is another identifier: the tag
	// that holds it is hashed as the node's ARN is, and joins it.
	var q snapshot.Node
	for _, c := range res.Tables.Nodes {
		if c.NativeID == secretscan.Hash(o.HashKey, "https://sqs.eu-west-1.amazonaws.com/111111111111/jobs-prod") {
			q = c
		}
	}
	if want := secretscan.Hash(o.HashKey, "arn:aws:sqs:eu-west-1:111111111111:jobs-prod"); q.ARNOrPath != want || q.Tags["queue_arn"] != want || q.Tags["env"] != "dev" {
		t.Errorf("queue: arn_or_path %q, tags %v, want queue_arn %q", q.ARNOrPath, q.Tags, want)
	}
	raw, _ := json.Marshal(res)
	for _, s := range []string{"web-frontend-7", "kubernetes.io/cluster", "acme-logs-app", "tags-test-key", "jobs-prod"} {
		if strings.Contains(string(raw), s) {
			t.Errorf("%q is in a hashed result", s)
		}
	}
}

func writeInventory(t *testing.T, resources string) []InventoryRead {
	t.Helper()
	p := filepath.Join(t.TempDir(), "aws.inventory.json")
	doc := `{"schema":"infraharvest/inventory/v1","run_id":"3f1c0b6e-8a52-4d3e-9f10-2c6a7d1e5b44","generated_at":"2026-11-25T09:30:00Z",
	 "tool":{"name":"infraharvest","version":"0.9.0"},"cloud":"aws","scopes":["aws/111111111111/eu-west-1"],"resources":[` + resources + `]}`
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	reads := ReadInventories([]string{p})
	if reads[0].Err != nil {
		t.Fatal(reads[0].Err)
	}
	return reads
}

func TestInventoryTagsWinOverStateTags(t *testing.T) {
	inv := writeInventory(t, `
	 {"type":"aws_instance","id":"i-0f00aa11","account":"111111111111","region":"eu-west-1","status":"managed","status_basis":"state","tags":{"env":"live","owner":"sre"}},
	 {"type":"aws_s3_bucket","id":"acme-logs-app","account":"111111111111","status":"managed","status_basis":"state"}`)
	extra := `,{"mode":"managed","type":"aws_s3_bucket","name":"logs","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"acme-logs-app","tags":{"env":"dev","from":"state"}}}]}`
	res := buildBoth(t, tagReads(t, extra), inv)

	// The inventory has tags: they are the node's, whole, and the state's are not mixed in.
	web := nodeByAddress(t, res.Tables, "aws_instance.web")
	if want := map[string]string{"env": "live", "owner": "sre"}; web.InventoryType != "aws_instance" || !maps.Equal(web.Tags, want) {
		t.Errorf("joined instance: tags %v, want %v", web.Tags, want)
	}
	// The inventory has none for the bucket: the state's stay.
	logs := nodeByAddress(t, res.Tables, "aws_s3_bucket.logs")
	if want := map[string]string{"env": "dev", "from": "state"}; logs.InventoryType != "aws_s3_bucket" || !maps.Equal(logs.Tags, want) {
		t.Errorf("joined bucket: tags %v, want %v", logs.Tags, want)
	}
	// Not in the inventory: the state's.
	if q := nodeByAddress(t, res.Tables, "google_storage_bucket.b"); q.Tags["team"] != "data" {
		t.Errorf("state-only resource: tags %v", q.Tags)
	}
	// The same inputs give the same rows.
	again, err := BuildAll(tagReads(t, extra), inv, opts)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(marshalSorted(t, res), marshalSorted(t, again)) {
		t.Error("two builds differ")
	}
}

func TestInventoryTagsWinInTheFixtures(t *testing.T) {
	res := buildBoth(t, fixtureReads(t), inventoryReads(t))
	// The state tags the VPC owner=platform; the inventory tags it env and Name.
	vpc := resourceNode(t, res.Tables, "aws_vpc", "vpc-0a1b")
	if want := map[string]string{"env": "prod", "Name": "main"}; !maps.Equal(vpc.Tags, want) {
		t.Errorf("vpc tags %v, want %v", vpc.Tags, want)
	}
}

func TestDataSourcesCarryNoTags(t *testing.T) {
	extra := `,{"mode":"data","type":"aws_ami","name":"base","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"ami-0aa11bb2","tags":{"looked":"up"}}}]},
	 {"mode":"managed","type":"aws_ami","name":"own","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"ami-0cc33dd4","tags":{"owned":"yes"}}}]}`
	tb := build(t, tagReads(t, extra)).Tables
	if got := nodeByAddress(t, tb, "data.aws_ami.base").Tags; len(got) != 0 {
		t.Errorf("a data source has tags %v", got)
	}
	if got := nodeByAddress(t, tb, "aws_ami.own").Tags; !maps.Equal(got, map[string]string{"owned": "yes"}) {
		t.Errorf("a managed resource has tags %v", got)
	}
}

// A resource an inventory is joined to has the inventory's tags, and with
// --drop-addresses the ones that hold its address, module path or Terraform
// name go too (a name shorter than four characters is not looked for).
func TestDropAddressesDropsJoinedInventoryTags(t *testing.T) {
	inv := writeInventory(t, `
	 {"type":"aws_instance","id":"i-0f00aa11","account":"111111111111","region":"eu-west-1","status":"managed","status_basis":"state",
	  "tags":{"env":"live","ref":"AWS_INSTANCE.WEB","Name":"web-1"}}`)
	o := opts
	o.DropAddresses = true
	res, err := BuildAll(tagReads(t, ""), inv, o)
	if err != nil {
		t.Fatal(err)
	}
	web := resourceNode(t, res.Tables, "aws_instance", "i-0f00aa11")
	if want := map[string]string{"env": "live", "Name": "web-1"}; !maps.Equal(web.Tags, want) {
		t.Errorf("joined instance: tags %v, want %v", web.Tags, want)
	}
}

// A tag that names a module call, an instance key or a short Terraform name
// gives the address away as much as one that holds the address: with
// --drop-addresses it goes. A key of four characters or more goes when it is
// held, a shorter one only when it is the whole value; a count index says
// nothing and stays.
func TestDropAddressesDropsTagsNamingACallOrAKey(t *testing.T) {
	const state = `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[
	 {"module":"module.network.module.app[\"s3\"]","mode":"managed","type":"aws_instance","name":"web","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"index_key":"east","attributes":{"id":"i-0f00bb22","tags":{"module":"network","tf":"web","TF2":"WEB","call":"app","key":"S3",
	   "region_key":"deploy-EAST-1","longer":"application","note":"not-related-to-it","team":"payments"}}}]},
	 {"module":"module.network","mode":"managed","type":"aws_instance","name":"db","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"index_key":0,"attributes":{"id":"i-0f00cc33","tags":{"slot":"0","idx":"0","cluster":"network-db","env":"prod"}}}]}]}`
	d, err := tfstate.Parse([]byte(state), tagsRoot)
	if err != nil {
		t.Fatal(err)
	}
	o := opts
	o.DropAddresses = true
	res, err := Build([]Read{{Location: tagsRoot, Docs: []tfstate.Document{d}}}, o)
	if err != nil {
		t.Fatal(err)
	}
	tags := map[string]map[string]string{}
	for _, n := range res.Tables.Nodes {
		if n.TFType == "aws_instance" {
			tags[n.NativeID] = n.Tags
		}
	}
	// Left: the tags that name none of the module calls (network, app), the
	// keys (s3, east) or the names (web, db) as a whole value or inside a
	// longer one.
	if want := (map[string]string{"longer": "application", "note": "not-related-to-it", "team": "payments"}); !maps.Equal(tags["i-0f00bb22"], want) {
		t.Errorf("web keeps %v, want %v", tags["i-0f00bb22"], want)
	}
	if want := (map[string]string{"slot": "0", "idx": "0", "env": "prod"}); !maps.Equal(tags["i-0f00cc33"], want) {
		t.Errorf("db keeps %v, want %v", tags["i-0f00cc33"], want)
	}
	if strings.Contains(strings.Join(res.Redaction.TagKeysDropped, ","), "module") {
		t.Errorf("a key that may be the address is listed: %v", res.Redaction.TagKeysDropped)
	}
}

// With a key, a tag that holds an identifier of the node besides its ID (the
// ARN of a queue whose ID is its URL) is hashed as the node's own ARN is, so
// that the two join, or dropped when its key holds one; an inventory's tags
// are treated the same.
func TestHashIDsHashesTagsHoldingTheARN(t *testing.T) {
	const arn = "arn:aws:sqs:eu-west-1:111111111111:jobs-prod"
	const url = "https://sqs.eu-west-1.amazonaws.com/111111111111/jobs-prod"
	state := `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[
	 {"mode":"managed","type":"aws_sqs_queue","name":"jobs","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"` + url + `","arn":"` + arn + `","tags":{"queue_arn":"` + arn + `","owner":"platform",
	   "note":"policy for ARN:AWS:SQS:EU-WEST-1:111111111111:JOBS-PROD only","` + arn + `":"1"}}}]}]}`
	d, err := tfstate.Parse([]byte(state), tagsRoot)
	if err != nil {
		t.Fatal(err)
	}
	key := []byte("tags-test-key-0123456789")
	o := opts
	o.HashKey = key
	reads := []Read{{Location: tagsRoot, Docs: []tfstate.Document{d}}}

	check := func(name string, res Result) {
		t.Helper()
		n := resourceNode(t, res.Tables, "aws_sqs_queue", secretscan.Hash(key, url))
		if want := secretscan.Hash(key, arn); n.ARNOrPath != want || n.Tags["queue_arn"] != want {
			t.Errorf("%s: arn_or_path %q, queue_arn %q, want both %q", name, n.ARNOrPath, n.Tags["queue_arn"], want)
		}
		if v := n.Tags["note"]; v == "" || strings.Contains(strings.ToLower(v), "arn:") {
			t.Errorf("%s: note is %q, want a hash", name, v)
		}
		if n.Tags["owner"] != "platform" || len(n.Tags) != 3 {
			t.Errorf("%s: tags %v", name, n.Tags)
		}
		raw, _ := json.Marshal(res)
		for _, s := range []string{"jobs-prod", "tags-test-key"} {
			if strings.Contains(strings.ToLower(string(raw)), s) {
				t.Errorf("%s: %q is in a hashed result", name, s)
			}
		}
	}
	res, err := Build(reads, o)
	if err != nil {
		t.Fatal(err)
	}
	check("state", res)

	// An inventory whose export did not hash: the ID is the import ID and the
	// cloud's ID is the ARN (an OCSF uid), with tags that hold it.
	inv := ocsfInventoryReads(t, arn, url)
	res, err = BuildAll(nil, inv, o)
	if err != nil {
		t.Fatal(err)
	}
	var found snapshot.Node
	for _, n := range res.Tables.Nodes {
		if n.Kind == snapshot.KindResource {
			found = n
		}
	}
	if want := secretscan.Hash(key, arn); found.ARNOrPath != want || found.Tags["queue_arn"] != want || len(found.Tags) != 2 {
		t.Errorf("inventory: arn_or_path %q, tags %v", found.ARNOrPath, found.Tags)
	}
}

// ocsfInventoryReads is an OCSF inventory of a queue the cloud calls by its
// ARN (uid) and the import ID is its URL (uid_alt), with tags that hold the ARN.
func ocsfInventoryReads(t *testing.T, arn, url string) []InventoryRead {
	t.Helper()
	doc := `{"schema":"infraharvest/ocsf-inventory/v1","run_id":"3f1c0b6e-8a52-4d3e-9f10-2c6a7d1e5b44","ocsf_version":"1.9.0",
	 "redaction":{"tag_keys_dropped":[],"ids_hashed":false,"hash_alg":"hmac-sha256","addresses_dropped":false},
	 "events":[{"time":1795600800000,"metadata":{"product":{"name":"infraharvest","version":"0.9.0"}},
	  "cloud":{"provider":"AWS","account":{"uid":"111111111111"},"region":"eu-west-1"},
	  "resources":[{"type":"aws_sqs_queue","uid":"` + arn + `","uid_alt":"` + url + `","labels":["status:unmanaged","status_basis:none"],
	   "tags":[{"name":"queue_arn","value":"` + arn + `"},{"name":"owner","value":"platform"},{"name":"` + arn + `","value":"1"}]}]}]}`
	p := filepath.Join(t.TempDir(), "aws.ocsf-inventory.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	reads := ReadInventories([]string{p})
	if reads[0].Err != nil {
		t.Fatal(reads[0].Err)
	}
	return reads
}

// An inventory that dropped every tag, or some keys, dropped them for the
// resources a state holds as well: the state's tags do not bring them back. A
// resource no such inventory lists keeps its state tags, so the manifest
// says every tag was dropped only when no node has one.
func TestInventoryDropsApplyToJoinedStateTags(t *testing.T) {
	write := func(redaction string) []InventoryRead {
		p := filepath.Join(t.TempDir(), "aws.inventory.json")
		doc := `{"schema":"infraharvest/inventory/v1","run_id":"3f1c0b6e-8a52-4d3e-9f10-2c6a7d1e5b44","generated_at":"2026-11-25T09:30:00Z",
		 "tool":{"name":"infraharvest","version":"0.9.0"},"cloud":"aws","scopes":["aws/111111111111/eu-west-1"],"resources":[
		 {"type":"aws_instance","id":"i-0f00aa11","account":"111111111111","region":"eu-west-1","status":"managed","status_basis":"state"}],
		 "redaction":` + redaction + `}`
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		reads := ReadInventories([]string{p})
		if reads[0].Err != nil {
			t.Fatal(reads[0].Err)
		}
		return reads
	}
	web := func(res Result) map[string]string { return nodeByAddress(t, res.Tables, "aws_instance.web").Tags }

	// Some keys dropped: those of the joined resource go, the rest stay, and
	// the manifest does not say all were dropped.
	res := buildBoth(t, tagReads(t, ""), write(`{"tag_keys_dropped":["team"],"all_tags_dropped":false}`))
	if want := (map[string]string{"env": "prod", "cost-centre": "42"}); !maps.Equal(web(res), want) {
		t.Errorf("keys dropped: tags %v, want %v", web(res), want)
	}
	if res.Redaction.AllTagsDropped || !slices.Contains(res.Redaction.TagKeysDropped, "team") {
		t.Errorf("redaction %+v", res.Redaction)
	}

	// All dropped: the joined resource has none, the others of the state keep
	// theirs, so the manifest says not all were dropped.
	res = buildBoth(t, tagReads(t, ""), write(`{"tag_keys_dropped":[],"all_tags_dropped":true}`))
	if got := web(res); len(got) != 0 {
		t.Errorf("all dropped: tags %v", got)
	}
	if got := nodeByAddress(t, res.Tables, "google_storage_bucket.b").Tags; got["team"] != "data" {
		t.Errorf("a resource no inventory lists: tags %v", got)
	}
	if res.Redaction.AllTagsDropped {
		t.Errorf("all_tags_dropped is true with tags on nodes: %+v", res.Redaction)
	}

	// All dropped and nothing else with a tag: true.
	const single = `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[
	 {"mode":"managed","type":"aws_instance","name":"web","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	  "instances":[{"attributes":{"id":"i-0f00aa11","arn":"arn:aws:ec2:eu-west-1:111111111111:instance/i-0f00aa11","tags":{"env":"dev"}}}]}]}`
	d, err := tfstate.Parse([]byte(single), tagsRoot)
	if err != nil {
		t.Fatal(err)
	}
	res = buildBoth(t, []Read{{Location: tagsRoot, Docs: []tfstate.Document{d}}}, write(`{"tag_keys_dropped":[],"all_tags_dropped":true}`))
	if len(web(res)) != 0 || !res.Redaction.AllTagsDropped {
		t.Errorf("tags %v, redaction %+v", web(res), res.Redaction)
	}
	// Without the inventory's flag, the state's tag stays and the flag is false.
	res = buildBoth(t, []Read{{Location: tagsRoot, Docs: []tfstate.Document{d}}}, write(`{"tag_keys_dropped":[],"all_tags_dropped":false}`))
	if web(res)["env"] != "dev" || res.Redaction.AllTagsDropped {
		t.Errorf("tags %v, redaction %+v", web(res), res.Redaction)
	}
}
