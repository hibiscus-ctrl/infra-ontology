// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/IgnatG/infraharvest/pkg/secretscan"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// Edge bases written by the inventory reader.
const (
	BasisCatalogueChild = "catalogue_child"
	BasisResourcePath   = "resource_path"
)

// BackendFile is the backend of an inventory source: a file.
const BackendFile = "file"

// InventoryRead is what one inventory file held, or why it could not be read.
type InventoryRead struct {
	Location string
	Inv      Inventory
	Err      error
}

// ReadInventories reads each file in order. A file that fails is recorded and
// does not stop the rest.
func ReadInventories(files []string) []InventoryRead {
	reads := make([]InventoryRead, 0, len(files))
	for _, f := range files {
		r := InventoryRead{Location: f}
		r.Inv, r.Err = ReadInventory(f)
		reads = append(reads, r)
	}
	return reads
}

func inventorySourceID(location string) string {
	sum := sha256.Sum256([]byte(location))
	return "inventory-" + hex.EncodeToString(sum[:])[:12]
}

// statusRank orders the statuses an inventory gives, so that the same resource
// listed by two documents keeps the one that knows most: a discover run lists
// everything as unmanaged, an import knows what it took over.
func statusRank(s string) int {
	switch s {
	case snapshot.Managed:
		return 3
	case snapshot.OtherIaC:
		return 2
	}
	return 1
}

// credentialLike reports whether text is, or holds, a credential or a URL
// with a user name, a password or a query string. A name or an address that
// does is not written down.
func credentialLike(s string) bool {
	return secretscan.CredentialFormat(s) != "" || Scrub(s) != strings.Join(strings.Fields(s), " ")
}

// clearCredential returns s, or "" when it looks like a credential.
func clearCredential(s string) string {
	if credentialLike(s) {
		return ""
	}
	return s
}

// invResource is a resource of an inventory, normalised and with the source
// that listed it.
type invResource struct {
	Resource
	source string
	sc     scope
	tfType string
	// hashed says the document it came from hashes its IDs.
	hashed bool
	// dropAll and dropKeys are what the export it came from dropped: every
	// tag, or the tags with these keys. They apply to the tags of a state
	// the resource is joined to.
	dropAll  bool
	dropKeys map[string]bool
}

type invKey struct{ cloud, account, typ, id string }

func (k invKey) String() string {
	return strings.Join([]string{k.cloud, k.account, k.typ, k.id}, "\x00")
}

// openInventories adds the sources of the inventories read and returns their
// resources, merged and in a fixed order: the same resource listed twice is
// one, with what each document knows of it.
func (b *builder) openInventories(reads []InventoryRead) []*invResource {
	sorted := slices.Clone(reads)
	sort.SliceStable(sorted, func(i, j int) bool { return Sanitise(sorted[i].Location) < Sanitise(sorted[j].Location) })
	merged := map[invKey]*invResource{}
	for _, r := range sorted {
		loc := Sanitise(r.Location)
		src := snapshot.Source{
			SourceID: b.invSourceID(loc), Kind: snapshot.SourceInventory, Backend: BackendFile, Location: loc,
			CollectedAt: b.at(), Collector: b.o.Collector, CollectorVersion: b.o.CollectorVersion,
			Status: snapshot.StatusOK,
		}
		if r.Err != nil {
			src.Status, src.Reason = snapshot.StatusFailed, Scrub(r.Err.Error())
			b.failedInventories = append(b.failedInventories, r)
			b.sources = append(b.sources, src)
			continue
		}
		inv := r.Inv
		src.DocumentSHA256, src.Collector, src.CollectorVersion = inv.Digest, firstOf(clearCredential(inv.Tool), src.Collector), firstOf(clearCredential(inv.ToolVersion), src.CollectorVersion)
		if !inv.GeneratedAt.IsZero() {
			src.CollectedAt = inv.GeneratedAt.UTC().Format(time.RFC3339)
		}
		if inv.Failed > 0 {
			src.Status = snapshot.StatusPartial
			src.Reason = fmt.Sprintf("the export counts %d resources whose import failed", inv.Failed)
			b.partialInventories++
		}
		b.sources = append(b.sources, src)
		b.inventories = append(b.inventories, inv)
		for _, res := range inv.Resources {
			b.mergeResource(merged, inv, src.SourceID, res)
		}
	}
	keys := make([]invKey, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	out := make([]*invResource, 0, len(keys))
	for _, k := range keys {
		out = append(out, merged[k])
	}
	return out
}

// mergeResource normalises one resource of an inventory into merged: it is
// left out if its ID is a credential, its name and address are dropped if they
// are, and its tags go through the secret detectors.
func (b *builder) mergeResource(merged map[invKey]*invResource, inv Inventory, source string, res Resource) {
	// An ID or a type that is a credential leaves the resource out: without
	// them it cannot be placed.
	if credentialLike(res.ID) || credentialLike(res.CloudID) || credentialLike(res.Type) {
		b.credentialIDs++
		return
	}
	for _, p := range []*string{&res.Name, &res.Address, &res.Module, &res.Root, &res.Account, &res.Region} {
		if credentialLike(*p) {
			*p = ""
		}
	}
	res.Root = Sanitise(res.Root)
	res.Tags = b.filterTags(res, inv.IDsHashed, res.CloudID)
	arn := ""
	if strings.HasPrefix(res.CloudID, "arn:") {
		arn = res.CloudID
	}
	sc := scopeOf(res.Cloud, res.ID, arn, "")
	if sc.path == "" && res.CloudID != "" {
		sc.path = res.CloudID
		if foldsCase(res.Cloud, sc.path) {
			sc.path = strings.ToLower(sc.path)
		}
	}
	r := &invResource{Resource: res, source: source, sc: sc, tfType: b.tm.Canonical(res.Type), hashed: inv.IDsHashed, dropAll: inv.AllTagsDropped}
	for _, k := range inv.TagKeysDropped {
		if r.dropKeys == nil {
			r.dropKeys = map[string]bool{}
		}
		r.dropKeys[k] = true
	}
	r.Account, r.Region = firstOf(sc.account, res.Account), firstOf(sc.region, res.Region)
	k := invKey{res.Cloud, r.Account, r.tfType, sc.id}
	old, ok := merged[k]
	if !ok {
		merged[k] = r
		return
	}
	if statusRank(r.Status) > statusRank(old.Status) {
		old.Status, old.Basis = r.Status, r.Basis
	}
	old.Name = firstOf(old.Name, r.Name)
	old.Address, old.Module, old.Root = firstOf(old.Address, r.Address), firstOf(old.Module, r.Module), firstOf(old.Root, r.Root)
	old.Region = firstOf(old.Region, r.Region)
	old.dropAll = old.dropAll || r.dropAll
	for k := range r.dropKeys {
		if old.dropKeys == nil {
			old.dropKeys = map[string]bool{}
		}
		old.dropKeys[k] = true
	}
	old.sc.path = firstOf(old.sc.path, r.sc.path)
	for tk, tv := range r.Tags {
		if old.Tags == nil {
			old.Tags = map[string]string{}
		}
		if _, set := old.Tags[tk]; !set {
			old.Tags[tk] = tv
		}
	}
}

// filterTags keeps the tags of a resource that do not look like secrets (and
// that the user did not ask to drop), and counts the ones that go. In a hashed
// build, others are the resource's identifiers besides its ID (its ARN, its
// cloud path): a tag that holds one is hashed or dropped, as for the ID.
func (b *builder) filterTags(res Resource, hashed bool, others ...string) map[string]string {
	f := b.tagFilter
	if hashed {
		// An inventory that hashed its IDs hashed the tags that gave them away.
		f = b.hashedTagFilter
	}
	kept := f.Tags(res.Tags, res.ID, res.Name)
	b.tagsDropped += len(res.Tags) - len(kept)
	if !hashed {
		// The filter looked for the ID and the name; the node's other
		// identifiers (its ARN or path) are hashed in its fields as well.
		kept = b.hideIdentifiers(kept, others...)
	}
	return kept
}

// stateIndex finds the resources a state manages by what an inventory calls
// them. The hashed maps are for an inventory that hashed its IDs: they hold
// the hashes, under the key of the build, of what the states hold.
type stateIndex struct {
	byID, byPath map[string][]string
	hByID, hPath map[string][]string
	// byType lists the nodes a state manages by cloud and Terraform type.
	byType map[string][]string
}

func indexKey(cloud, typ, v string) string { return cloud + "|" + typ + "|" + v }

func (b *builder) indexState() stateIndex {
	idx := stateIndex{
		byID: map[string][]string{}, byPath: map[string][]string{},
		hByID: map[string][]string{}, hPath: map[string][]string{}, byType: map[string][]string{},
	}
	for _, n := range b.nodes {
		if n.Kind != snapshot.KindResource || n.ManagedStatus != snapshot.Managed || n.Address == "" {
			continue
		}
		tk := n.Cloud + "|" + n.TFType
		idx.byType[tk] = append(idx.byType[tk], n.NodeID)
		if n.NativeID != "" {
			k := indexKey(n.Cloud, n.TFType, n.NativeID)
			idx.byID[k] = append(idx.byID[k], n.NodeID)
		}
		if n.ARNOrPath != "" {
			k := indexKey(n.Cloud, n.TFType, n.ARNOrPath)
			idx.byPath[k] = append(idx.byPath[k], n.NodeID)
		}
		if raw, ok := b.raw[n.NodeID]; ok {
			// The export hashed the ID as the provider wrote it, which
			// may differ in case from the one Azure resources are
			// compared by here: both are looked for.
			for _, v := range []string{raw.id, strings.ToLower(raw.id), n.NativeID} {
				if v != "" {
					k := indexKey(n.Cloud, n.TFType, b.h(v))
					idx.hByID[k] = appendOnce(idx.hByID[k], n.NodeID)
				}
			}
			for _, v := range []string{raw.arn, n.ARNOrPath} {
				if v != "" {
					k := indexKey(n.Cloud, n.TFType, b.h(v))
					idx.hPath[k] = appendOnce(idx.hPath[k], n.NodeID)
				}
			}
		}
		b.stateManaged = append(b.stateManaged, n.NodeID)
	}
	sort.Strings(b.stateManaged)
	return idx
}

func appendOnce(s []string, v string) []string {
	if slices.Contains(s, v) {
		return s
	}
	return append(s, v)
}

// match returns the nodes of the state that are the same thing as r: the same
// type and the same ID, or the same ARN or resource path, in an account and a
// region that do not contradict each other. A resource of an inventory that
// hashed its IDs is matched by hash, which needs the key of the build.
func (b *builder) match(idx stateIndex, r *invResource) []string {
	byID, byPath := idx.byID, idx.byPath
	if r.hashed {
		if b.key == nil {
			return nil
		}
		byID, byPath = idx.hByID, idx.hPath
	}
	var found []string
	add := func(ids []string) {
		for _, id := range ids {
			if n := b.nodes[id]; compatible(n, r) && !slices.Contains(found, id) {
				found = append(found, id)
			}
		}
	}
	add(byID[indexKey(r.Cloud, r.tfType, r.sc.id)])
	if r.sc.path != "" {
		add(byPath[indexKey(r.Cloud, r.tfType, r.sc.path)])
	}
	sort.Strings(found)
	return found
}

// compatible says the account and region of a node and a resource do not
// disagree: either may lack them.
func compatible(n snapshot.Node, r *invResource) bool {
	return (n.Account == "" || r.Account == "" || n.Account == r.Account) &&
		(n.Region == "" || r.Region == "" || n.Region == r.Region)
}

// expectedInState says a state manages a resource of the type and in the
// account of r, so that an inventory that lists none of them has probably
// been hashed with another key.
func (b *builder) expectedInState(idx stateIndex, r *invResource) bool {
	for _, id := range idx.byType[r.Cloud+"|"+r.tfType] {
		if compatible(b.nodes[id], r) {
			return true
		}
	}
	return false
}

// placement is where an inventory resource goes: into the nodes of the states
// that manage it, or, with none, into a node of its own.
type placement struct {
	r   *invResource
	ids []string
}

// addInventories puts the resources of the inventories into the rows: a
// resource a state manages is that state's node, with what the inventory adds;
// any other is a node of its own, with the status the inventory gives it.
func (b *builder) addInventories(reads []InventoryRead) {
	resources := b.openInventories(reads)
	idx := b.indexState()
	placed := make([]placement, 0, len(resources))
	matched, expected := map[string]int{}, map[string]bool{}
	for _, r := range resources {
		ids := b.match(idx, r)
		if id := b.nodeIDOf(r); len(ids) == 0 && b.isManagedNode(id) {
			ids = []string{id}
		}
		if r.hashed && b.key != nil {
			if len(ids) > 0 {
				matched[r.source]++
			} else if b.expectedInState(idx, r) {
				expected[r.source] = true
			}
		}
		placed = append(placed, placement{r, ids})
	}
	// A hashed inventory that lists things the states manage and matches
	// none of them was hashed with another key: what it calls unmanaged says
	// nothing.
	for src := range expected {
		if matched[src] == 0 {
			b.mismatched[src] = true
		}
	}
	for _, p := range placed {
		if len(p.ids) > 0 {
			for _, id := range p.ids {
				b.join(id, p.r)
			}
			continue
		}
		b.addInventoryNode(p.r)
	}
	b.inventoryEdges()
}

func (b *builder) nodeIDOf(r *invResource) string {
	if r.hashed {
		return b.hashedNodeID(snapshot.KindResource, r.Cloud, r.Account, r.Region, r.tfType, r.sc.id)
	}
	return b.nodeID(snapshot.KindResource, r.Cloud, r.Account, r.Region, r.tfType, r.sc.id)
}

func (b *builder) isManagedNode(id string) bool {
	n, ok := b.nodes[id]
	return ok && n.Kind == snapshot.KindResource && n.ManagedStatus == snapshot.Managed && n.Address != ""
}

// join adds what an inventory knows of a resource to the node a state made of
// it. The state stays the source of the node, and is what makes it managed.
func (b *builder) join(id string, r *invResource) {
	n := b.nodes[id]
	n.Account, n.Region = firstOf(n.Account, r.Account), firstOf(n.Region, r.Region)
	n.InventoryType = r.Type
	if n.Name == "" && r.Name != "" {
		n.Name = r.Name
		b.markIfHashed(id, r, "name")
	}
	if n.ARNOrPath == "" && r.sc.path != "" {
		n.ARNOrPath = r.sc.path
		b.markIfHashed(id, r, "arn_or_path")
	}
	// The inventory's tags win where it has any: they are what the cloud
	// holds now. The state's stay for a resource the inventory has none for.
	// What the export dropped, it dropped for the resource: the state's tags
	// do not bring it back.
	if len(r.Tags) > 0 {
		n.Tags = r.Tags
	} else {
		n.Tags = b.applyUpstreamDrops(n.Tags, r)
	}
	b.nodes[id] = n
	b.invSource[id] = firstOf(b.invSource[id], r.source)
	b.joined[id] = true
}

// applyUpstreamDrops removes from the tags of a state's node what the export
// of the inventory it is joined to dropped: every tag, or the tags with the
// keys it lists.
func (b *builder) applyUpstreamDrops(tags map[string]string, r *invResource) map[string]string {
	if len(tags) == 0 || (!r.dropAll && len(r.dropKeys) == 0) {
		return tags
	}
	kept := make(map[string]string, len(tags))
	for k, v := range tags {
		if r.dropAll || r.dropKeys[k] {
			b.tagsDropped++
			continue
		}
		kept[k] = v
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

// markIfHashed notes that a field of a node was taken from r, which an
// inventory hashed, so that it is not hashed twice.
func (b *builder) markIfHashed(id string, r *invResource, fields ...string) {
	if r.hashed {
		b.markHashed(id, fields...)
	}
}

// addInventoryNode adds the node of a resource that no state holds.
func (b *builder) addInventoryNode(r *invResource) {
	status, conf := r.Status, snapshot.Observed
	if r.Basis == "tag" {
		// Terraform's tags say it is managed: a guess, not a state.
		conf = snapshot.Inferred
	}
	if r.hashed && b.hadStates && status == snapshot.Unmanaged && (b.key == nil || b.mismatched[r.source]) {
		// Its ID is a hash the states cannot be searched for, or one made
		// with another key: not being in them says nothing.
		status = snapshot.Unknown
	}
	if status == snapshot.Managed && b.hadStates {
		b.claimedManaged++
	}
	n := snapshot.Node{
		NodeID: b.nodeIDOf(r), Kind: snapshot.KindResource, Cloud: r.Cloud, Account: r.Account, Region: r.Region,
		InventoryType: r.Type, NativeID: r.sc.id, ARNOrPath: r.sc.path, Name: r.Name,
		Address: r.Address, Module: r.Module, Root: r.Root, Tags: r.Tags,
		ManagedStatus: status, Confidence: conf, SourceID: r.source,
	}
	if hasTerraformPrefix(r.tfType) {
		n.TFType = r.tfType
	}
	_, existed := b.nodes[n.NodeID]
	b.addNode(n)
	if !existed {
		b.markIfHashed(n.NodeID, r, "native_id", "arn_or_path", "name", "address", "module", "root")
	}
	b.invSource[n.NodeID] = r.source
}

// hasTerraformPrefix tells a Terraform resource type from another name.
func hasTerraformPrefix(t string) bool {
	for _, p := range []string{"aws_", "azurerm_", "azapi_", "google_"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// inventoryEdges adds the containment the inventory shows: a resource that
// the catalogue lists as a part of another with the same ID (the versioning of
// a bucket), and an Azure resource inside the resource its ID's path names.
// Both are computed from identifiers, not read from the cloud.
func (b *builder) inventoryEdges() {
	var ids []string
	byType := map[string][]string{}
	byNative := map[string][]string{}
	parents := map[string][]string{}
	// Nodes are compared by native ID as it will be written: in a hashed
	// build, the IDs of states are hashed here as the inventories' are.
	native := func(id string, n snapshot.Node) string { return b.hashField(id, "native_id", n.NativeID) }
	for id, n := range b.nodes {
		if n.Kind != snapshot.KindResource || n.NativeID == "" || isDataAddress(n.Address) {
			continue
		}
		ids = append(ids, id)
		k := indexKey(n.Cloud, n.TFType, native(id, n))
		byType[k] = append(byType[k], id)
		byNative[n.Cloud+"|"+native(id, n)] = append(byNative[n.Cloud+"|"+native(id, n)], id)
		if n.TFType != "" {
			for _, child := range b.tm.Children(n.TFType) {
				if !slices.Contains(parents[child], n.TFType) {
					parents[child] = append(parents[child], n.TFType)
				}
			}
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		n := b.nodes[id]
		for _, p := range parents[n.TFType] {
			for _, pid := range byType[indexKey(n.Cloud, p, native(id, n))] {
				if src := firstOf(b.invSource[id], b.invSource[pid]); src != "" && pid != id && sameScope(n, b.nodes[pid]) {
					b.addEdge(snapshot.EdgeContainedIn, BasisCatalogueChild, snapshot.Computed, id, pid, src)
				}
			}
		}
		if n.Cloud != "azure" || b.invSource[id] == "" {
			continue
		}
		for _, anc := range azureParents(n.NativeID) {
			if to := byNative["azure|"+b.h(anc)]; len(to) > 0 && to[0] != id {
				sort.Strings(to)
				b.addEdge(snapshot.EdgeContainedIn, BasisResourcePath, snapshot.Computed, id, to[0], b.invSource[id])
				break
			}
		}
	}
}

// isDataAddress says an address is a data source's: what it reads is not
// necessarily what a state manages.
func isDataAddress(a string) bool {
	return strings.HasPrefix(a, "data.") || strings.Contains(a, ".data.")
}

// sameScope says two nodes are not in different accounts or regions.
func sameScope(a, c snapshot.Node) bool {
	return (a.Account == "" || c.Account == "" || a.Account == c.Account) &&
		(a.Region == "" || c.Region == "" || a.Region == c.Region)
}

// azureParents lists the resource IDs an Azure resource ID is inside, nearest
// first: the resource its path continues from, and the resource group. The ID
// is in lower case.
func azureParents(id string) []string {
	i := strings.Index(id, "/providers/")
	if i < 0 {
		return nil
	}
	rest := strings.Split(strings.Trim(id[i+len("/providers/"):], "/"), "/")
	var out []string
	// rest is the namespace, then pairs of a type and a name.
	for n := len(rest) - 2; n >= 3; n -= 2 {
		out = append(out, id[:i]+"/providers/"+strings.Join(rest[:n], "/"))
	}
	if strings.Contains(id[:i], "/resourcegroups/") {
		out = append(out, id[:i])
	}
	return out
}

// inventoryLimits says, in plain text, what the inventories leave open.
func (b *builder) inventoryLimits() []string {
	var s []string
	if b.credentialIDs > 0 {
		s = append(s, fmt.Sprintf("%d inventory resources have an ID that looks like a credential and are left out.", b.credentialIDs))
	}
	if b.tagsDropped > 0 {
		s = append(s, fmt.Sprintf("%d tags look like secrets, or were dropped by request, and are not kept.", b.tagsDropped))
	}
	switch n := b.hashedInventories(); {
	case n > 0 && b.key == nil:
		s = append(s, fmt.Sprintf("%d inventories hash their IDs, so their resources cannot be matched to state; where states were read, those the inventory calls unmanaged are unknown. Build with --hash-ids and the same key to match them.", n))
	case len(b.mismatched) > 0:
		s = append(s, fmt.Sprintf("%d inventories hash their IDs and list resources of the types and accounts the states manage, but match none of them, so they were probably hashed with another key; what they call unmanaged is unknown.", len(b.mismatched)))
	}
	if b.partialInventories > 0 {
		s = append(s, fmt.Sprintf("%d inventories count resources whose import failed.", b.partialInventories))
	}
	if len(b.stateManaged) > 0 {
		if n := b.claimedManaged; n > 0 {
			s = append(s, fmt.Sprintf("%d resources are managed according to an inventory but are in none of the states read; they keep that status.", n))
		}
		if n := b.notInInventory(); n > 0 {
			s = append(s, fmt.Sprintf("%d resources in the states read are not in the inventories, though these list their type and account: they may have been deleted, or not be listed. They stay managed.", n))
		}
	}
	return s
}

func (b *builder) hashedInventories() int {
	n := 0
	for _, inv := range b.inventories {
		if inv.IDsHashed {
			n++
		}
	}
	return n
}

// notInInventory counts the resources of the states that no inventory lists,
// where an inventory lists their type in their account: an inventory that
// does not cover them cannot say they are gone.
func (b *builder) notInInventory() int {
	types, accounts := map[string]bool{}, map[string]map[string]bool{}
	for _, n := range b.nodes {
		if b.invSource[n.NodeID] == "" || n.Kind != snapshot.KindResource || n.TFType == "" {
			continue
		}
		types[n.Cloud+"|"+n.TFType] = true
		if accounts[n.Cloud] == nil {
			accounts[n.Cloud] = map[string]bool{}
		}
		accounts[n.Cloud][n.Account] = true
	}
	count := 0
	for _, id := range b.stateManaged {
		n := b.nodes[id]
		if b.joined[id] || !types[n.Cloud+"|"+n.TFType] {
			continue
		}
		if n.Account == "" || accounts[n.Cloud][n.Account] {
			count++
		}
	}
	return count
}

// redaction says which tag keys were dropped, and whether all were.
func (b *builder) redaction(t snapshot.Tables) snapshot.Redaction {
	keys := append(b.tagFilter.DroppedKeys(), b.hashedTagFilter.DroppedKeys()...)
	all := b.o.DropAllTags
	upstream := 0
	for _, inv := range b.inventories {
		for _, k := range inv.TagKeysDropped {
			if secretscan.CredentialFormat(k) == "" {
				keys = append(keys, k)
			}
		}
		if inv.AllTagsDropped {
			upstream++
		}
	}
	if len(b.inventories) > 0 && upstream == len(b.inventories) {
		all = true
	}
	// Every tag was dropped only if no node carries one: a state's tags stay
	// for a resource no inventory that dropped its own is joined to.
	for _, n := range t.Nodes {
		if len(n.Tags) > 0 {
			all = false
			break
		}
	}
	red := snapshot.Redaction{HashAlgorithm: "none", TagKeysDropped: keys, AllTagsDropped: all, AddressesDropped: b.o.DropAddresses}
	if b.key != nil {
		red.HashAlgorithm, red.IDsHashed = HashAlgorithm, true
	}
	return red
}
