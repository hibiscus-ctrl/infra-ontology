// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package snapshot

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"

	"github.com/parquet-go/parquet-go"
)

// Row schemas of the tables, recorded in each file's metadata and in the
// manifest.
const (
	NodeSchema   = "infra-ontology/node/v1"
	EdgeSchema   = "infra-ontology/edge/v1"
	SourceSchema = "infra-ontology/source/v1"

	schemaKey = "infra-ontology.schema"
)

// The Parquet rows. Every column but a source's serial is a required string,
// with "" for "not known", so a row has no null and the file has no choice
// to make about one. Tags are a list of key and value pairs sorted by key: a
// Parquet map is written in the order of a Go map, which is random.
type (
	tagRow struct {
		Key   string `parquet:"key"`
		Value string `parquet:"value"`
	}
	nodeRow struct {
		NodeID        string   `parquet:"node_id"`
		Kind          string   `parquet:"kind,dict"`
		Cloud         string   `parquet:"cloud,dict"`
		Account       string   `parquet:"account,dict"`
		Region        string   `parquet:"region,dict"`
		TFType        string   `parquet:"tf_type,dict"`
		InventoryType string   `parquet:"inventory_type,dict"`
		NativeID      string   `parquet:"native_id"`
		ARNOrPath     string   `parquet:"arn_or_path"`
		Name          string   `parquet:"name"`
		Address       string   `parquet:"address"`
		Module        string   `parquet:"module,dict"`
		Root          string   `parquet:"root,dict"`
		ManagedStatus string   `parquet:"managed_status,dict"`
		Environment   string   `parquet:"environment,dict"`
		Tags          []tagRow `parquet:"tags,list"`
		Confidence    string   `parquet:"confidence,dict"`
		SourceID      string   `parquet:"source_id,dict"`
	}
	edgeRow struct {
		EdgeID     string `parquet:"edge_id"`
		FromID     string `parquet:"from_id"`
		ToID       string `parquet:"to_id"`
		Kind       string `parquet:"kind,dict"`
		Confidence string `parquet:"confidence,dict"`
		Basis      string `parquet:"basis,dict"`
		SourceID   string `parquet:"source_id,dict"`
	}
	sourceRow struct {
		SourceID         string `parquet:"source_id"`
		Kind             string `parquet:"kind,dict"`
		Backend          string `parquet:"backend,dict"`
		Location         string `parquet:"location"`
		Workspace        string `parquet:"workspace,dict"`
		Serial           *int64 `parquet:"serial,optional"`
		Lineage          string `parquet:"lineage"`
		TerraformVersion string `parquet:"terraform_version,dict"`
		DocumentSHA256   string `parquet:"document_sha256"`
		CollectedAt      string `parquet:"collected_at"`
		Collector        string `parquet:"collector,dict"`
		CollectorVersion string `parquet:"collector_version,dict"`
		Status           string `parquet:"status,dict"`
		Reason           string `parquet:"reason"`
	}
)

func (n Node) row() nodeRow {
	r := nodeRow{
		NodeID: n.NodeID, Kind: n.Kind, Cloud: n.Cloud, Account: n.Account, Region: n.Region,
		TFType: n.TFType, InventoryType: n.InventoryType, NativeID: n.NativeID, ARNOrPath: n.ARNOrPath,
		Name: n.Name, Address: n.Address, Module: n.Module, Root: n.Root, ManagedStatus: n.ManagedStatus,
		Environment: n.Environment, Confidence: n.Confidence, SourceID: n.SourceID,
	}
	for k, v := range n.Tags {
		r.Tags = append(r.Tags, tagRow{k, v})
	}
	slices.SortFunc(r.Tags, func(a, b tagRow) int { return compare(a.Key, b.Key) })
	return r
}

func (r nodeRow) node() Node {
	n := Node{
		NodeID: r.NodeID, Kind: r.Kind, Cloud: r.Cloud, Account: r.Account, Region: r.Region,
		TFType: r.TFType, InventoryType: r.InventoryType, NativeID: r.NativeID, ARNOrPath: r.ARNOrPath,
		Name: r.Name, Address: r.Address, Module: r.Module, Root: r.Root, ManagedStatus: r.ManagedStatus,
		Environment: r.Environment, Confidence: r.Confidence, SourceID: r.SourceID,
	}
	if len(r.Tags) > 0 {
		n.Tags = make(map[string]string, len(r.Tags))
		for _, t := range r.Tags {
			n.Tags[t.Key] = t.Value
		}
	}
	return n
}

func (e Edge) row() edgeRow  { return edgeRow(e) }
func (r edgeRow) edge() Edge { return Edge(r) }

func (s Source) row() sourceRow    { return sourceRow(s) }
func (r sourceRow) source() Source { return Source(r) }

func compare(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// writeParquet encodes rows, already sorted, as one Parquet file. The writer
// settings are fixed so that the same rows always give the same bytes: one
// row group, no compression, plain data pages, the dictionary limit left at
// its default, no clock and no file name in the metadata, and the row schema's
// id in the key and value metadata.
func writeParquet[T any](rows []T, schema string) ([]byte, error) {
	var buf bytes.Buffer
	w := parquet.NewGenericWriter[T](&buf,
		parquet.Compression(&parquet.Uncompressed),
		parquet.CreatedBy("infra-ontology", "", ""),
		parquet.KeyValueMetadata(schemaKey, schema),
		parquet.MaxRowsPerRowGroup(1<<40),
		parquet.DataPageVersion(2),
		parquet.DataPageStatistics(true),
	)
	if len(rows) > 0 {
		if _, err := w.Write(rows); err != nil {
			return nil, fmt.Errorf("write %s: %w", schema, err)
		}
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("write %s: %w", schema, err)
	}
	return buf.Bytes(), nil
}

// readParquet decodes a whole Parquet file into rows and checks that the file
// says it holds the schema it should. A file with more columns than the row
// type is read as long as it has all of the row type's (an additive minor
// version).
func readParquet[T any](data []byte, schema string) ([]T, error) {
	f, err := parquet.OpenFile(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, fmt.Errorf("not a Parquet file: %w", err)
	}
	if got, ok := f.Lookup(schemaKey); !ok || got != schema {
		return nil, fmt.Errorf("file declares schema %q, want %q", got, schema)
	}
	// The footer says how many rows follow: refuse a table past the limit
	// before decoding any of it.
	if n := f.NumRows(); n > int64(maxTableRows) {
		return nil, fmt.Errorf("%d rows, over the limit of %d", n, maxTableRows)
	}
	r := parquet.NewGenericReader[T](f)
	defer r.Close()
	// The row count comes from the file, which may not be ours yet: let append
	// grow the slice instead of trusting it for an allocation.
	var rows []T
	for {
		buf := make([]T, 1024) // fresh each time: the reader may reuse a row's slices
		n, err := r.Read(buf)
		rows = append(rows, buf[:n]...)
		if len(rows) > maxTableRows { // the footer was not the whole truth
			return nil, fmt.Errorf("more than the limit of %d rows", maxTableRows)
		}
		if errors.Is(err, io.EOF) {
			return rows, nil
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", schema, err)
		}
	}
}

func encodeNodes(nodes []Node) ([]byte, error) {
	rows := make([]nodeRow, len(nodes))
	for i, n := range nodes {
		rows[i] = n.row()
	}
	return writeParquet(rows, NodeSchema)
}

func decodeNodes(data []byte) ([]Node, error) {
	rows, err := readParquet[nodeRow](data, NodeSchema)
	if err != nil {
		return nil, err
	}
	out := make([]Node, len(rows))
	for i, r := range rows {
		out[i] = r.node()
	}
	return out, nil
}

func encodeEdges(edges []Edge) ([]byte, error) {
	rows := make([]edgeRow, len(edges))
	for i, e := range edges {
		rows[i] = e.row()
	}
	return writeParquet(rows, EdgeSchema)
}

func decodeEdges(data []byte) ([]Edge, error) {
	rows, err := readParquet[edgeRow](data, EdgeSchema)
	if err != nil {
		return nil, err
	}
	out := make([]Edge, len(rows))
	for i, r := range rows {
		out[i] = r.edge()
	}
	return out, nil
}

func encodeSources(sources []Source) ([]byte, error) {
	rows := make([]sourceRow, len(sources))
	for i, s := range sources {
		rows[i] = s.row()
	}
	return writeParquet(rows, SourceSchema)
}

func decodeSources(data []byte) ([]Source, error) {
	rows, err := readParquet[sourceRow](data, SourceSchema)
	if err != nil {
		return nil, err
	}
	out := make([]Source, len(rows))
	for i, r := range rows {
		out[i] = r.source()
	}
	return out, nil
}
