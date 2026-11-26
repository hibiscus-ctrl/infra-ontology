// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"strings"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// A resource a state holds and no inventory lists is missing only where an
// inventory can say so: it lists the resource's cloud, account, region and
// type, and that listing was complete. Anything less leaves the resource
// managed, because an inventory that never looked cannot say a resource is
// gone. Nothing here reads a value of a resource: it compares identifiers
// and the counts a document gives of what it could not list.

// listing is what one inventory document lists, for deciding what its
// absences mean.
type listing struct {
	source string
	inv    Inventory
	// types are the counts the document gives for each type, under the
	// Terraform type it is joined by.
	types map[string]Counts
	// leftOut says a resource of the document was left out of the snapshot
	// (its ID looks like a credential), so that it is not known to be absent.
	leftOut bool
	// keys are the resources it lists, as the build merges them (see
	// invKey); groups the Azure resource groups it lists a resource in.
	keys   map[string]bool
	groups map[string]bool
	// scopeDone says, for each scope the document calls complete, the
	// Terraform types it lists in full there; typeDone the types it calls
	// complete. Absent is not complete.
	scopeDone map[string]map[string]bool
	typeDone  map[string]bool
	// proven holds the (cloud, account, type) of the states' resources this
	// listing joined: IDs of that type compare between state and inventory.
	proven map[string]bool
}

func newListing(source string, inv Inventory, canonical func(string) string) *listing {
	l := &listing{
		source: source, inv: inv, types: map[string]Counts{},
		keys: map[string]bool{}, groups: map[string]bool{}, proven: map[string]bool{},
		scopeDone: map[string]map[string]bool{}, typeDone: map[string]bool{},
	}
	if inv.Coverage != nil {
		for typ, c := range inv.Coverage.Types {
			t := canonical(typ)
			l.types[t] = addCounts(l.types[t], c)
		}
		// Two types of the document may be one Terraform type: complete only
		// where each is.
		for typ, done := range inv.Coverage.TypeDone {
			t := canonical(typ)
			prev, seen := l.typeDone[t]
			l.typeDone[t] = done && (!seen || prev)
		}
		for scope, d := range inv.Coverage.ScopeDone {
			if !d.Complete {
				continue
			}
			types := make(map[string]bool, len(d.Types))
			for typ := range d.Types {
				types[canonical(typ)] = true
			}
			l.scopeDone[scope] = types
		}
	}
	return l
}

// accountKey folds an Azure subscription to lower case, as the IDs are.
func accountKey(cloud, account string) string {
	if cloud == "azure" {
		return strings.ToLower(account)
	}
	return account
}

// add notes a resource the document lists.
func (l *listing) add(k invKey, id string, hashed bool) {
	l.keys[k.String()] = true
	if k.account == "" {
		return
	}
	if k.cloud == "azure" && !hashed {
		if g := azureGroup(id); g != "" {
			l.groups[accountKey(k.cloud, k.account)+"|"+g] = true
		}
	}
}

// azureGroup is the resource group an Azure resource ID, in lower case, is
// in: the ID up to and including the group's name. "" for an ID that is in
// none.
func azureGroup(id string) string {
	parts := strings.Split(strings.ToLower(id), "/")
	// "", subscriptions, <sub>, resourcegroups, <group>, ...
	if len(parts) > 4 && parts[1] == "subscriptions" && parts[3] == "resourcegroups" && parts[4] != "" {
		return strings.Join(parts[:5], "/")
	}
	return ""
}

// cloudOfScope is the cloud of a scope's provider (aws, azure or google).
func cloudOfScope(provider string) string { return cloudNames[provider] }

// usable says the document can show that a resource is missing at all: it is
// an inventory/v1 document that says how complete it is (totals, types and
// scopes, and the filters of the run), in which no kind of filter narrowed
// the listing (--id, --tag, --where, --services or --skip, one group, a
// listing in part), no import failed, the selection of the run left no
// resource out and no resource was left out of the import (include or
// exclude lists only some of what is there), with no resource of it left out of the snapshot, and which, if it
// hashes its IDs, was matched to the states with their key.
func (b *builder) usable(l *listing) bool {
	switch {
	case l.inv.Schema != SchemaInventory, l.inv.Coverage == nil, l.inv.Filters == nil, l.inv.Filters.Any(), l.inv.Failed > 0, l.leftOut:
		return false
	case l.inv.IDsHashed && (b.key == nil || b.mismatched[l.source]):
		return false
	}
	t := l.inv.Coverage.Totals
	return t.Failed == 0 && t.Excluded == 0 && t.LeftOut == 0
}

// covers says the listing lists the type of n in the account and region of n
// in full: every scope of the document that is the account and region has
// no failed, skipped, excluded or left-out resource, is complete and names
// the type among those it listed in full (those it found none of too), the type
// has no failed, skipped, excluded or left-out resource and, where the
// document has an entry for it, is complete, and its IDs of the type compare
// to state (a resource of the type was joined). For Azure, which has no region in an ID, the account is
// the scope, and the listing must list the resource group of n too: a listing
// of one group is not a listing of the subscription.
func (b *builder) covers(l *listing, n snapshot.Node) bool {
	if !b.usable(l) {
		return false
	}
	if n.Region == "" && n.Cloud != "azure" {
		return false
	}
	c := l.inv.Coverage
	scopes := 0
	for _, s := range l.inv.Scopes {
		parts := strings.SplitN(s, "/", 3)
		if len(parts) != 3 || cloudOfScope(parts[0]) != n.Cloud || accountKey(n.Cloud, parts[1]) != accountKey(n.Cloud, n.Account) {
			continue
		}
		if n.Cloud != "azure" && parts[2] != n.Region {
			continue
		}
		scopes++
		counts, ok := c.Scopes[s]
		if !ok {
			counts = c.Totals
		}
		if !counts.Complete() || !l.scopeDone[s][n.TFType] {
			return false
		}
	}
	if scopes == 0 {
		return false
	}
	counts, ok := l.types[n.TFType]
	if !ok {
		counts = c.Totals
	}
	if !counts.Complete() {
		return false
	}
	// A type the document found none of has no entry: the scope's complete
	// types are what says it was listed.
	if _, ok := l.types[n.TFType]; ok && !l.typeDone[n.TFType] {
		return false
	}
	if !l.proven[n.Cloud+"|"+accountKey(n.Cloud, n.Account)+"|"+n.TFType] {
		return false
	}
	if n.Cloud == "azure" {
		return l.groups[accountKey(n.Cloud, n.Account)+"|"+azureGroup(n.NativeID)] && azureGroup(n.NativeID) != ""
	}
	return true
}

// markMissing marks as missing the resources of the states that no inventory
// lists although one lists them in full. It is the last step of joining: a
// resource that was joined is not missing, and it needs every inventory to
// have been read, so that one that failed cannot be the one that lists it.
func (b *builder) markMissing() {
	if len(b.failedInventories) > 0 || len(b.listings) == 0 {
		return
	}
	for id, keys := range b.joinedKeys {
		n := b.nodes[id]
		for _, l := range b.listings {
			for _, k := range keys {
				if l.keys[k.String()] {
					l.proven[n.Cloud+"|"+accountKey(n.Cloud, n.Account)+"|"+n.TFType] = true
				}
			}
		}
	}
	for _, id := range b.stateManaged {
		n := b.nodes[id]
		if b.joined[id] || n.Kind != snapshot.KindResource || n.ManagedStatus != snapshot.Managed ||
			n.TFType == "" || n.Account == "" || n.NativeID == "" || isDataAddress(n.Address) {
			continue
		}
		for _, l := range b.listings {
			if b.covers(l, n) {
				n.ManagedStatus, n.Confidence = snapshot.Missing, snapshot.Computed
				b.nodes[id] = n
				b.missing++
				break
			}
		}
	}
}
