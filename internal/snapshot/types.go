// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

// Package snapshot writes, reads, verifies and compares snapshots: immutable
// folders of Parquet tables (nodes, edges and sources) and a manifest whose
// content hash names the snapshot. The types match the JSON Schemas under
// schemas/. A snapshot holds identifiers, addresses and links, never
// attribute values; tags are the one kind of value it keeps.
package snapshot

// Format is the format and major version the manifest declares. A reader
// rejects any other.
const Format = "infra-ontology/snapshot/v1"

// FormatMinor is the minor version this package writes. Within a major,
// changes only add columns, kinds and members.
const FormatMinor = 0

// File names inside a snapshot folder.
const (
	ManifestFile = "manifest.json"
	NodesFile    = "nodes.parquet"
	EdgesFile    = "edges.parquet"
	SourcesFile  = "sources.parquet"
)

// Node kinds.
const (
	KindResource   = "resource"
	KindModuleCall = "module_call"
	KindStateRoot  = "state_root"
	KindAccount    = "account"
	KindExternal   = "external"
)

// Managed statuses.
const (
	Managed   = "managed"
	OtherIaC  = "other_iac"
	Unmanaged = "unmanaged"
	Unknown   = "unknown"
)

// Confidence values of a node or an edge.
const (
	Observed = "observed"
	Computed = "computed"
	Inferred = "inferred"
)

// Edge kinds written in v0. The set is open: a later minor version may add
// kinds, and a reader accepts one it does not know.
const (
	EdgeDependsOn    = "depends_on"
	EdgeContainedIn  = "contained_in"
	EdgeDefinedIn    = "defined_in"
	EdgeReadsStateOf = "reads_state_of"
)

// Source kinds and statuses.
const (
	SourceState     = "state"
	SourceInventory = "inventory"
	SourcePlan      = "plan"

	StatusOK      = "ok"
	StatusPartial = "partial"
	StatusFailed  = "failed"
)

// Node is one row of the nodes table (schemas/node-v1.schema.json).
type Node struct {
	NodeID        string            `json:"node_id"`
	Kind          string            `json:"kind"`
	Cloud         string            `json:"cloud,omitempty"`
	Account       string            `json:"account,omitempty"`
	Region        string            `json:"region,omitempty"`
	TFType        string            `json:"tf_type,omitempty"`
	InventoryType string            `json:"inventory_type,omitempty"`
	NativeID      string            `json:"native_id,omitempty"`
	ARNOrPath     string            `json:"arn_or_path,omitempty"`
	Name          string            `json:"name,omitempty"`
	Address       string            `json:"address,omitempty"`
	Module        string            `json:"module,omitempty"`
	Root          string            `json:"root,omitempty"`
	ManagedStatus string            `json:"managed_status"`
	Environment   string            `json:"environment,omitempty"`
	Tags          map[string]string `json:"tags,omitempty"`
	Confidence    string            `json:"confidence"`
	SourceID      string            `json:"source_id"`
}

// Edge is one row of the edges table (schemas/edge-v1.schema.json). It reads
// from refers to, or depends on, to.
type Edge struct {
	EdgeID     string `json:"edge_id"`
	FromID     string `json:"from_id"`
	ToID       string `json:"to_id"`
	Kind       string `json:"kind"`
	Confidence string `json:"confidence"`
	Basis      string `json:"basis"`
	SourceID   string `json:"source_id"`
}

// Source is one row of the sources table (schemas/source-v1.schema.json).
type Source struct {
	SourceID         string `json:"source_id"`
	Kind             string `json:"kind"`
	Backend          string `json:"backend,omitempty"`
	Location         string `json:"location,omitempty"`
	Workspace        string `json:"workspace,omitempty"`
	Serial           *int64 `json:"serial,omitempty"`
	Lineage          string `json:"lineage,omitempty"`
	TerraformVersion string `json:"terraform_version,omitempty"`
	DocumentSHA256   string `json:"document_sha256,omitempty"`
	CollectedAt      string `json:"collected_at"`
	Collector        string `json:"collector,omitempty"`
	CollectorVersion string `json:"collector_version,omitempty"`
	Status           string `json:"status"`
	Reason           string `json:"reason,omitempty"`
}

// Tables are the rows of a snapshot.
type Tables struct {
	Nodes   []Node
	Edges   []Edge
	Sources []Source
}

// Manifest is manifest.json (schemas/snapshot-v1.schema.json).
type Manifest struct {
	Format         string         `json:"format"`
	FormatMinor    int            `json:"format_minor"`
	SnapshotID     string         `json:"snapshot_id"`
	ParentID       string         `json:"parent_id"`
	Label          string         `json:"label"`
	CreatedAt      string         `json:"created_at"`
	Tool           Tool           `json:"tool"`
	Status         string         `json:"status"`
	Tables         []TableInfo    `json:"tables"`
	SourcesSummary SourcesSummary `json:"sources_summary"`
	Redaction      Redaction      `json:"redaction"`
	Coverage       Coverage       `json:"coverage"`
	Limits         string         `json:"limits"`
}

// Tool names the program that wrote a snapshot.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// TableInfo describes one table file: its hash and size.
type TableInfo struct {
	Name   string `json:"name"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
	Rows   int    `json:"rows"`
	Schema string `json:"schema"`
}

// SourcesSummary counts the sources and dates the oldest and newest read.
type SourcesSummary struct {
	Count             int            `json:"count"`
	ByKind            map[string]int `json:"by_kind"`
	OldestCollectedAt string         `json:"oldest_collected_at,omitempty"`
	NewestCollectedAt string         `json:"newest_collected_at,omitempty"`
}

// Redaction says what was hidden before the snapshot was written.
type Redaction struct {
	HashAlgorithm    string   `json:"hash_algorithm"`
	IDsHashed        bool     `json:"ids_hashed"`
	AddressesDropped bool     `json:"addresses_dropped"`
	TagKeysDropped   []string `json:"tag_keys_dropped"`
	AllTagsDropped   bool     `json:"all_tags_dropped"`
}

// Coverage says what the snapshot covers and what could not be read.
type Coverage struct {
	Clouds        []string       `json:"clouds"`
	Accounts      []string       `json:"accounts"`
	Types         []string       `json:"types"`
	FailedSources []FailedSource `json:"failed_sources"`
}

// FailedSource is a source that did not read in full.
type FailedSource struct {
	SourceID string `json:"source_id"`
	Status   string `json:"status"`
	Reason   string `json:"reason"`
}

// Answer is the citation record that comes with every answer
// (schemas/answer-v1.schema.json). The query layer fills it in a later change.
type Answer struct {
	Query       string       `json:"query"`
	QueryHash   string       `json:"query_hash"`
	StoredQuery string       `json:"stored_query,omitempty"`
	SnapshotID  string       `json:"snapshot_id"`
	Dialect     string       `json:"dialect"`
	Engine      string       `json:"engine"`
	RowCount    int          `json:"row_count"`
	Truncated   bool         `json:"truncated"`
	ResultHash  string       `json:"result_hash"`
	Limits      AnswerLimits `json:"limits"`
}

// AnswerLimits says what the data behind an answer cannot tell you.
type AnswerLimits struct {
	OldestSource   string   `json:"oldest_source,omitempty"`
	FailedSources  int      `json:"failed_sources"`
	UncoveredTypes []string `json:"uncovered_types,omitempty"`
}
