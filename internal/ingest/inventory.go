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
	"maps"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

// The documents infraharvest's export writes that this package reads. The
// format is infraharvest's, published as JSON Schema under its schemas/ folder;
// nothing here imports its internal packages, and what is read is a projection
// of the document: the decoder skips every member this package does not name,
// so nothing it does not name can reach a snapshot.
const (
	SchemaInventory     = "infraharvest/inventory/v1"
	SchemaOCSFInventory = "infraharvest/ocsf-inventory/v1"
)

// Inventory is what one exported document says, as the resources it lists and
// how complete it is.
type Inventory struct {
	// Location is the file the document was read from, as it was named.
	Location string
	// Schema is the document's schema: SchemaInventory or SchemaOCSFInventory.
	Schema string
	// Tool and ToolVersion name the program that wrote it.
	Tool, ToolVersion string
	// GeneratedAt is when the document says it was made (the time of its
	// newest event, for an OCSF inventory).
	GeneratedAt time.Time
	// IDsHashed says the document's IDs, names and addresses are HMACs, so
	// that they cannot be matched to state.
	IDsHashed bool
	// TagKeysDropped are the tag keys the export dropped, AllTagsDropped
	// that it dropped every tag.
	TagKeysDropped []string
	AllTagsDropped bool
	// Failed is how many resources the run behind the document could not
	// import (inventory/v1 counts them; an OCSF inventory does not).
	Failed int
	// Scopes are the scopes the document says it lists (provider, account
	// and region, such as aws/123456789012/eu-west-2), and Coverage how
	// complete its listing of them was. Coverage is nil for a document that
	// does not say (an OCSF inventory, or an inventory/v1 without it).
	Scopes   []string
	Coverage *Coverage
	// Filters says which kinds of filter narrowed the listing of any scope. It
	// is nil for a document that does not say (one an earlier release wrote),
	// which is taken as narrowed.
	Filters   *Filters
	Resources []Resource
	// Digest is the SHA-256 of what is kept of the document.
	Digest string
}

// Coverage is what an inventory/v1 document says of what its run could not
// list or left out: the resources it failed to read, skipped, left out of the
// import (excluded by its selection, or left out of the output), in all, by
// scope and by type. Only these counts are kept: nothing of a resource's
// values is in them. A document that does not give the totals, the types and
// the scopes has no Coverage (see parseInventoryV1).
type Coverage struct {
	Totals Counts
	// Scopes and Types are keyed by the scope and by the Terraform type as
	// the document writes them.
	Scopes, Types map[string]Counts
	// ScopeDone and TypeDone say what the document calls a complete listing:
	// of a scope (and the types listed in full in it, those it found none of
	// too), and of a type (in every scope listed). Absent is not complete.
	ScopeDone map[string]ScopeDone
	TypeDone  map[string]bool
}

// ScopeDone is a scope whose document says it was listed in full, and the
// types listed in full in it.
type ScopeDone struct {
	Complete bool
	Types    map[string]bool
}

// Filters are the kinds of filter that narrow a listing: --id, --tag, --where,
// --services or --skip, a provider scope of one group, and a listing in part.
// A kind the document does not give is true: it does not say it was not used.
type Filters struct{ ID, Tag, Where, Services, Group, Partial bool }

// Any says some kind of filter narrowed the listing.
func (f Filters) Any() bool {
	return f.ID || f.Tag || f.Where || f.Services || f.Group || f.Partial
}

// Counts are the resources of a part of a listing that could not be read
// (Failed), that the run skipped (Skipped), that its selection left out
// (Excluded), or that it left out of the import (LeftOut). A listing with none
// is complete: the run looked at every resource there and imported or listed
// it.
type Counts struct{ Failed, Skipped, Excluded, LeftOut int }

// Complete says no resource of the part was failed, skipped, excluded or
// left out.
func (c Counts) Complete() bool {
	return c.Failed == 0 && c.Skipped == 0 && c.Excluded == 0 && c.LeftOut == 0
}

// Resource is one resource of an inventory.
type Resource struct {
	// Cloud is aws, azure or gcp; Account and Region are as the document
	// gives them ("" where it has none).
	Cloud, Account, Region string
	// Type is the Terraform type the document names the resource by.
	Type string
	// ID is the import ID, and CloudID what the cloud itself calls the
	// resource (an ARN, or an Azure resource ID) where the document says.
	ID, CloudID string
	Name        string
	Tags        map[string]string
	// Status is managed, other_iac or unmanaged; Basis says whether a state,
	// a tag or nothing says so (state, tag or none).
	Status, Basis string
	// Address, Module and Root say where an import wrote the resource's
	// configuration, when it did (an OCSF inventory only).
	Address, Module, Root string
}

// ReadInventory reads the exported document in file. A file that is not an
// inventory/v1 or ocsf-inventory/v1 document is an error, and so is one with a
// resource that lacks a type or an ID.
func ReadInventory(file string) (Inventory, error) {
	f, err := os.Open(file)
	if err != nil {
		return Inventory{}, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxInventoryBytes+1))
	if err != nil {
		return Inventory{}, err
	}
	if int64(len(raw)) > maxInventoryBytes {
		return Inventory{}, fmt.Errorf("larger than %d bytes, which an inventory file may not be", maxInventoryBytes)
	}
	inv, err := ParseInventory(raw)
	inv.Location = file
	return inv, err
}

// ParseInventory reads an exported document, of either schema.
func ParseInventory(raw []byte) (Inventory, error) {
	var head struct {
		Schema string `json:"schema"`
	}
	if err := decode(raw, &head); err != nil {
		return Inventory{}, err
	}
	var (
		inv Inventory
		err error
	)
	switch head.Schema {
	case SchemaInventory:
		inv, err = parseInventoryV1(raw)
	case SchemaOCSFInventory:
		inv, err = parseOCSF(raw)
	case "":
		return Inventory{}, errors.New("not an infraharvest document: it has no schema member")
	default:
		return Inventory{}, fmt.Errorf("schema %q is not %s or %s", Scrub(head.Schema), SchemaInventory, SchemaOCSFInventory)
	}
	if err != nil {
		return Inventory{}, err
	}
	inv.Schema = head.Schema
	inv.Digest = digestOf(inv)
	return inv, nil
}

// decode reads one JSON value and nothing after it. Members that the target
// does not name are skipped.
func decode(raw []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("not JSON of the expected shape: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("data after the JSON document")
	}
	return nil
}

var cloudNames = map[string]string{"aws": "aws", "azure": "azure", "google": "gcp", "AWS": "aws", "Azure": "azure", "GCP": "gcp"}

var statuses = map[string]bool{"managed": true, "other_iac": true, "unmanaged": true}

type redactionV1 struct {
	TagKeysDropped []string `json:"tag_keys_dropped"`
	AllTagsDropped bool     `json:"all_tags_dropped"`
	IDsHashed      bool     `json:"ids_hashed"`
}

type inventoryV1 struct {
	GeneratedAt string `json:"generated_at"`
	Tool        struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tool"`
	Cloud     string   `json:"cloud"`
	Scopes    []string `json:"scopes"`
	Resources []struct {
		Type        string            `json:"type"`
		ID          string            `json:"id"`
		Account     string            `json:"account"`
		Status      string            `json:"status"`
		StatusBasis string            `json:"status_basis"`
		Name        string            `json:"name"`
		Region      string            `json:"region"`
		Tags        map[string]string `json:"tags"`
	} `json:"resources"`
	Redaction redactionV1 `json:"redaction"`
	Coverage  *struct {
		Totals *countsV1 `json:"totals"`
		Types  []struct {
			Type     string   `json:"type"`
			Counts   countsV1 `json:"counts"`
			Complete *bool    `json:"complete"`
		} `json:"types"`
		Scopes []struct {
			Scope         string   `json:"scope"`
			Counts        countsV1 `json:"counts"`
			Complete      *bool    `json:"complete"`
			CompleteTypes []string `json:"complete_types"`
		} `json:"scopes"`
	} `json:"coverage"`
	Filters *struct {
		ID, Tag, Where, Services, Group, Partial *bool
	} `json:"filters"`
}

// countsV1 is the part of a document's counts this package reads.
type countsV1 struct {
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
	Excluded int `json:"excluded"`
	LeftOut  int `json:"left_out"`
}

func parseInventoryV1(raw []byte) (Inventory, error) {
	var d inventoryV1
	if err := decode(raw, &d); err != nil {
		return Inventory{}, err
	}
	cloud, ok := cloudNames[d.Cloud]
	if !ok {
		return Inventory{}, fmt.Errorf("cloud %q is not aws, azure or google", Scrub(d.Cloud))
	}
	at, err := time.Parse(time.RFC3339, d.GeneratedAt)
	if err != nil {
		return Inventory{}, fmt.Errorf("generated_at: %w", err)
	}
	inv := Inventory{
		Tool: d.Tool.Name, ToolVersion: d.Tool.Version, GeneratedAt: at.UTC(),
		IDsHashed: d.Redaction.IDsHashed, TagKeysDropped: d.Redaction.TagKeysDropped,
		AllTagsDropped: d.Redaction.AllTagsDropped, Scopes: d.Scopes,
	}
	if d.Coverage != nil && d.Coverage.Totals != nil {
		inv.Failed = d.Coverage.Totals.Failed
	}
	// A document that lacks the totals, the types or the scopes, such as
	// "coverage":{}, does not say how complete its listing was: it has no
	// Coverage, rather than one that counts nothing.
	if c := d.Coverage; c != nil && c.Totals != nil && c.Types != nil && c.Scopes != nil {
		inv.Coverage = &Coverage{
			Totals: Counts(*c.Totals), Scopes: make(map[string]Counts, len(c.Scopes)), Types: make(map[string]Counts, len(c.Types)),
		}
		inv.Coverage.ScopeDone, inv.Coverage.TypeDone = map[string]ScopeDone{}, map[string]bool{}
		for _, s := range c.Scopes {
			inv.Coverage.Scopes[s.Scope] = addCounts(inv.Coverage.Scopes[s.Scope], Counts(s.Counts))
			inv.Coverage.mergeScopeDone(s.Scope, s.Complete, s.CompleteTypes)
		}
		for _, t := range c.Types {
			inv.Coverage.Types[t.Type] = addCounts(inv.Coverage.Types[t.Type], Counts(t.Counts))
			_, seen := inv.Coverage.TypeDone[t.Type]
			inv.Coverage.TypeDone[t.Type] = t.Complete != nil && *t.Complete && (!seen || inv.Coverage.TypeDone[t.Type])
		}
	}
	if f := d.Filters; f != nil {
		// A kind the document leaves out is not known to be unused.
		used := func(b *bool) bool { return b == nil || *b }
		inv.Filters = &Filters{
			ID: used(f.ID), Tag: used(f.Tag), Where: used(f.Where), Services: used(f.Services), Group: used(f.Group), Partial: used(f.Partial),
		}
	}
	for i, r := range d.Resources {
		if r.Type == "" || r.ID == "" {
			return Inventory{}, fmt.Errorf("resources[%d]: a type and an id are required", i)
		}
		if !statuses[r.Status] {
			return Inventory{}, fmt.Errorf("resources[%d]: status %q is not managed, other_iac or unmanaged", i, Scrub(r.Status))
		}
		inv.Resources = append(inv.Resources, Resource{
			Cloud: cloud, Account: knownAccount(r.Account), Region: r.Region, Type: r.Type, ID: r.ID,
			Name: r.Name, Tags: r.Tags, Status: r.Status, Basis: r.StatusBasis,
		})
	}
	return inv, nil
}

// mergeScopeDone notes what the document says of the completeness of a scope.
// A scope it names twice is complete only where both say so, in the types
// both name.
func (c *Coverage) mergeScopeDone(scope string, complete *bool, types []string) {
	d := ScopeDone{Complete: complete != nil && *complete, Types: make(map[string]bool, len(types))}
	for _, t := range types {
		d.Types[t] = true
	}
	if prev, ok := c.ScopeDone[scope]; ok {
		d.Complete = d.Complete && prev.Complete
		for t := range d.Types {
			if !prev.Types[t] {
				delete(d.Types, t)
			}
		}
	}
	c.ScopeDone[scope] = d
}

func addCounts(a, b Counts) Counts {
	return Counts{a.Failed + b.Failed, a.Skipped + b.Skipped, a.Excluded + b.Excluded, a.LeftOut + b.LeftOut}
}

// countFields are the counts of c, as the digest has them.
func countFields(c Counts) []string {
	f := []string{strconv.Itoa(c.Failed), strconv.Itoa(c.Skipped)}
	if c.Excluded > 0 || c.LeftOut > 0 {
		// Only when counted, so that the digest of a document that counts neither
		// is what it was.
		f = append(f, strconv.Itoa(c.Excluded), strconv.Itoa(c.LeftOut))
	}
	return f
}

// knownAccount is the account of a resource, "" where infraharvest could not
// tell it (it writes "unknown").
func knownAccount(a string) string {
	if a == "unknown" {
		return ""
	}
	return a
}

type ocsfInventory struct {
	Redaction redactionV1 `json:"redaction"`
	Events    []struct {
		Time     int64 `json:"time"`
		Metadata struct {
			Product struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			} `json:"product"`
		} `json:"metadata"`
		Cloud struct {
			Provider string `json:"provider"`
			Account  *struct {
				UID string `json:"uid"`
			} `json:"account"`
			Region string `json:"region"`
		} `json:"cloud"`
		Resources []struct {
			Type   string   `json:"type"`
			UID    string   `json:"uid"`
			UIDAlt string   `json:"uid_alt"`
			Name   string   `json:"name"`
			Region string   `json:"region"`
			Labels []string `json:"labels"`
			Tags   []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"tags"`
			IaC *struct {
				Address       string `json:"address"`
				ModuleAddress string `json:"module_address"`
				Path          string `json:"path"`
				StateKey      string `json:"state_key"`
			} `json:"iac"`
		} `json:"resources"`
	} `json:"events"`
}

func parseOCSF(raw []byte) (Inventory, error) {
	var d ocsfInventory
	if err := decode(raw, &d); err != nil {
		return Inventory{}, err
	}
	inv := Inventory{
		IDsHashed: d.Redaction.IDsHashed, TagKeysDropped: d.Redaction.TagKeysDropped,
		AllTagsDropped: d.Redaction.AllTagsDropped,
	}
	var newest int64
	for i, e := range d.Events {
		cloud, ok := cloudNames[e.Cloud.Provider]
		if !ok {
			return Inventory{}, fmt.Errorf("events[%d]: cloud provider %q is not AWS, Azure or GCP", i, Scrub(e.Cloud.Provider))
		}
		newest = max(newest, e.Time)
		inv.Tool, inv.ToolVersion = e.Metadata.Product.Name, e.Metadata.Product.Version
		account := ""
		if e.Cloud.Account != nil {
			account = knownAccount(e.Cloud.Account.UID)
		}
		for j, r := range e.Resources {
			if r.Type == "" || r.UID == "" {
				return Inventory{}, fmt.Errorf("events[%d].resources[%d]: a type and a uid are required", i, j)
			}
			res := Resource{
				Cloud: cloud, Account: account, Region: firstOf(r.Region, e.Cloud.Region), Type: r.Type,
				ID: r.UID, Name: r.Name, Status: "unmanaged", Basis: "none",
			}
			if r.UIDAlt != "" {
				// The uid is what the cloud calls it; the import ID, which
				// state holds, is the alternative.
				res.ID, res.CloudID = r.UIDAlt, r.UID
			}
			for _, l := range r.Labels {
				switch k, v, _ := strings.Cut(l, ":"); k {
				case "status":
					if statuses[v] {
						res.Status = v
					}
				case "status_basis":
					res.Basis = v
				}
			}
			if len(r.Tags) > 0 {
				res.Tags = make(map[string]string, len(r.Tags))
				for _, t := range r.Tags {
					res.Tags[t.Name] = t.Value
				}
			}
			if r.IaC != nil {
				res.Address, res.Module = r.IaC.Address, r.IaC.ModuleAddress
				res.Root = firstOf(r.IaC.StateKey, r.IaC.Path)
			}
			inv.Resources = append(inv.Resources, res)
		}
	}
	if newest > 0 {
		inv.GeneratedAt = time.UnixMilli(newest).UTC()
	}
	return inv, nil
}

// digestOf is the SHA-256 of what is kept of an inventory, in the order of
// its resources: like a state's, it is not the hash of the file's bytes, but
// changes whenever anything this reader keeps changes.
func digestOf(inv Inventory) string {
	h := sha256.New()
	w := func(fields ...string) {
		for _, f := range fields {
			h.Write([]byte(f))
			h.Write([]byte{0})
		}
		h.Write([]byte{'\n'})
	}
	w(inv.Schema, inv.Tool, inv.ToolVersion, inv.GeneratedAt.Format(time.RFC3339))
	if inv.Coverage != nil {
		// What the listing could not read decides what its absences mean, so
		// a change to it changes the digest.
		c := inv.Coverage
		w(append([]string{"coverage"}, countFields(c.Totals)...)...)
		for _, scope := range slices.Sorted(maps.Keys(inv.Coverage.Scopes)) {
			w(append([]string{"scope", scope}, countFields(c.Scopes[scope])...)...)
		}
		for _, typ := range slices.Sorted(maps.Keys(inv.Coverage.Types)) {
			w(append([]string{"type", typ}, countFields(c.Types[typ])...)...)
		}
		for _, scope := range slices.Sorted(maps.Keys(c.ScopeDone)) {
			d := c.ScopeDone[scope]
			w(append([]string{"scope-done", scope, fmt.Sprint(d.Complete)}, slices.Sorted(maps.Keys(d.Types))...)...)
		}
		for _, typ := range slices.Sorted(maps.Keys(c.TypeDone)) {
			w("type-done", typ, fmt.Sprint(c.TypeDone[typ]))
		}
		w(append([]string{"scopes"}, slices.Sorted(slices.Values(inv.Scopes))...)...)
	}
	if f := inv.Filters; f != nil {
		w("filters", fmt.Sprint(f.ID, f.Tag, f.Where, f.Services, f.Group, f.Partial))
	}
	for _, r := range inv.Resources {
		w(r.Cloud, r.Account, r.Region, r.Type, r.ID, r.CloudID, r.Name, r.Status, r.Basis, r.Address, r.Module, r.Root)
		keys := make([]string, 0, len(r.Tags))
		for k := range r.Tags {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			w("tag", k, r.Tags[k])
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
