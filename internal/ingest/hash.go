// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"regexp"
	"strings"

	"github.com/IgnatG/infraharvest/pkg/secretscan"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// HashAlgorithm is what the manifest says a hashed snapshot was hashed with:
// the HMAC-SHA256 of infraharvest export --hash-ids, which gives the same
// hash for the same key.
const HashAlgorithm = "hmac-sha256"

// withheld replaces the reason a source could not be read in a hashed
// snapshot: an error holds the paths and bucket names the hashing hides.
const withheld = "could not be read; the cause is not kept because the snapshot hashes locations"

// rawID is the ID and ARN a state gave a resource, as it wrote them.
type rawID struct{ id, arn string }

// h is the hash of s under the key, or s itself without one.
func (b *builder) h(s string) string { return secretscan.Hash(b.key, s) }

// nodeID is the identifier of a node: the hex SHA-256 of its kind, cloud,
// account, region, type and native ID (see snapshot.NodeID) or, with a key,
// the HMAC of the same fields with the native ID hashed. It is the same for
// the same key, and nothing but the key tells which ID it is of.
func (b *builder) nodeID(kind, cloud, account, region, typ, native string) string {
	if b.key == nil {
		return snapshot.NodeID(kind, cloud, account, region, typ, native)
	}
	return b.hashedNodeID(kind, cloud, account, region, typ, b.h(native))
}

// hashedNodeID is nodeID for a native ID that is a hash already.
func (b *builder) hashedNodeID(kind, cloud, account, region, typ, hashed string) string {
	if b.key == nil {
		return snapshot.NodeID(kind, cloud, account, region, typ, hashed)
	}
	return secretscan.Hash(b.key, strings.Join([]string{kind, cloud, account, region, typ, hashed, ""}, "\x00"))
}

// sourceID is the identifier of a source read from location. With a key it
// comes from the hash of the location, so that the identifier cannot be
// checked against a guess.
func (b *builder) sourceID(location string) string { return sourceID(b.h(location)) }

// invSourceID is sourceID for an inventory.
func (b *builder) invSourceID(location string) string { return inventorySourceID(b.h(location)) }

// markHashed says that the fields of a node (by their column name) hold
// hashes already, as an inventory wrote them.
func (b *builder) markHashed(id string, fields ...string) {
	for _, f := range fields {
		b.preHashed[id+"\x00"+f] = true
	}
}

// hashField hashes the value of a column of a node, unless it is one an
// inventory hashed.
func (b *builder) hashField(id, field, v string) string {
	if b.preHashed[id+"\x00"+field] {
		return v
	}
	return b.h(v)
}

// redactTables is the last step of a hashed build, and the only place that
// hashes the text of the rows: everything a node, a source or a failure can
// say about where a thing is or what it is called is replaced by its hash.
// The identifiers of nodes, edges and sources were hashed when they were made.
// Types, accounts, regions, tags (which the tag filter dealt with), counts and
// times stay as they are. Without a key it hashes nothing. With DropAddresses
// it also leaves every Terraform address, the module path that is part of one,
// the name a state gave a resource or a module call (the last part of its
// address) and a module call's native ID out of the nodes; the matching of
// state to inventory is done by then, so nothing needs them. A tag whose key
// or value holds one of them (tf_address = module.network.aws_vpc.main, or
// Name = main) is dropped with them, before they are cleared. Node IDs are
// not changed: a diff joins on them.
func (b *builder) redactTables(t snapshot.Tables) snapshot.Tables {
	if b.key == nil && !b.o.DropAddresses {
		return t
	}
	if b.o.DropAddresses {
		states := map[string]bool{}
		for _, s := range t.Sources {
			states[s.SourceID] = s.Kind == snapshot.SourceState
		}
		for i, n := range t.Nodes {
			name := ""
			if n.Kind == snapshot.KindResource && states[n.SourceID] {
				name = n.Name
			}
			n.Tags = b.dropAddressTags(n.Tags, n.Address, n.Module, name)
			n.Address, n.Module = "", ""
			switch {
			case n.Kind == snapshot.KindModuleCall:
				// Its native ID is the state and the call's address, and its
				// name is the last part of that address, with its key.
				n.NativeID, n.Name = "", ""
			case n.Kind == snapshot.KindResource && states[n.SourceID]:
				// A state made the node, so its name is the Terraform name,
				// the last part of the address. A joined inventory only
				// fills a name the state lacks, which goes too. A node only
				// an inventory holds keeps the name the cloud gives it.
				n.Name = ""
			}
			t.Nodes[i] = n
		}
	}
	if b.key == nil {
		return t
	}
	for i, n := range t.Nodes {
		id := n.NodeID
		n.NativeID = b.hashField(id, "native_id", n.NativeID)
		n.ARNOrPath = b.hashField(id, "arn_or_path", n.ARNOrPath)
		n.Name = b.hashField(id, "name", n.Name)
		n.Address = b.hashField(id, "address", n.Address)
		n.Module = b.hashField(id, "module", n.Module)
		n.Root = b.hashField(id, "root", n.Root)
		t.Nodes[i] = n
	}
	for i, s := range t.Sources {
		s.Location = b.h(s.Location)
		s.Workspace = b.h(s.Workspace)
		s.DocumentSHA256 = b.h(s.DocumentSHA256)
		if s.Status == snapshot.StatusFailed && s.Reason != "" {
			s.Reason = withheld
		}
		t.Sources[i] = s
	}
	return t
}

// minNamedTF is the shortest Terraform name that a tag holding it gives away:
// a shorter one would be found in tags that do not name the resource. It is
// secretscan's threshold for IDs and names.
const minNamedTF = 4

// instanceKey matches the key of a count or for_each instance in an address.
var instanceKey = regexp.MustCompile(`\[[^\]]*\]`)

// dropAddressTags returns tags less those whose key or value holds, in any
// case, an address, a module path or a Terraform name (left empty where it is
// not one, as for a resource only an inventory holds) that is long enough to
// say something. It runs before the tag filter on the tags of a state, which
// the filter may hash, and again on the tables, for the tags an inventory
// brought, and before the address is cleared. The tags that go are counted
// with the other dropped tags, and their keys are not listed, since a key may
// be the address.
func (b *builder) dropAddressTags(tags map[string]string, address, module, name string) map[string]string {
	if len(tags) == 0 {
		return tags
	}
	var needles []string
	add := func(v string, shortest int) {
		for _, s := range []string{v, instanceKey.ReplaceAllString(v, "")} {
			if len(s) >= shortest && s != "" {
				needles = append(needles, strings.ToLower(s))
			}
		}
	}
	add(address, 1)
	add(module, 1)
	add(name, minNamedTF)
	if len(needles) == 0 {
		return tags
	}
	holds := func(s string) bool {
		s = strings.ToLower(s)
		for _, w := range needles {
			if strings.Contains(s, w) {
				return true
			}
		}
		return false
	}
	kept := make(map[string]string, len(tags))
	for k, v := range tags {
		if holds(k) || holds(v) {
			b.tagsDropped++
			continue
		}
		kept[k] = v
	}
	if len(kept) == len(tags) {
		return tags
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}
