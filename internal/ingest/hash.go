// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"encoding/hex"
	"regexp"
	"sort"
	"strconv"
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

// Withheld is withheld for the command, which prints it in place of the cause
// of a failure in a hashed build.
const Withheld = withheld

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
// inventory hashed. The mark is a claim: a value is kept as it is only if it
// has the shape of a hash (see hashedValue), and any other is hashed here.
func (b *builder) hashField(id, field, v string) string {
	if b.preHashed[id+"\x00"+field] && hashedValue(v) {
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
	var ids identifierSet
	if b.key != nil {
		// Before the addresses and module paths are cleared.
		ids = identifiers(t)
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
	b.hideTagIdentifiers(t, ids)
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

// quotedKey matches the key of an instance in an address, quoted (for_each)
// or not (count).
var quotedKey = regexp.MustCompile(`\[("(?:[^"\\]|\\.)*"|[^\]]*)\]`)

// addressNames returns the names an address and a module path hold besides
// the address itself: each module call's name, and each quoted instance key
// (a for_each key; a number is a count index, which says nothing).
func addressNames(address, module string) []string {
	var out []string
	for _, a := range []string{module, address} {
		parts := splitTop(a)
		for i := 0; i+1 < len(parts) && parts[i] == "module"; i += 2 {
			if n := instanceKey.ReplaceAllString(parts[i+1], ""); n != "" {
				out = append(out, n)
			}
		}
		for _, m := range quotedKey.FindAllStringSubmatch(a, -1) {
			k := m[1]
			if len(k) < 2 || k[0] != '"' || k[len(k)-1] != '"' {
				continue
			}
			if u, err := strconv.Unquote(k); err == nil && u != "" {
				out = append(out, u)
			}
		}
	}
	return out
}

// dropAddressTags returns tags less those that give away an address, a module
// path, a Terraform name, a module call's name or an instance key (left empty
// where it is not one, as for a resource only an inventory holds). A tag goes
// when its key or value holds, in any case, the address or the module path, or
// a name or a key of four characters or more; or, for any length, when its
// key or value is, in any case, the Terraform name, a call's name or a key
// (tf = web). It runs before the tag filter on the tags of a state, which
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
	var exact []string
	for _, e := range append([]string{name}, addressNames(address, module)...) {
		if e != "" {
			exact = append(exact, strings.ToLower(e))
			add(e, minNamedTF)
		}
	}
	if len(needles) == 0 && len(exact) == 0 {
		return tags
	}
	holds := func(s string) bool {
		l := strings.ToLower(s)
		for _, w := range needles {
			if strings.Contains(l, w) {
				return true
			}
		}
		for _, e := range exact {
			if l == e {
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

// minIdentifier is the shortest identifier of a node that a tag holding it
// gives away (secretscan's threshold for IDs and names).
const minIdentifier = 4

// hashedValue says a tag value is a hash already: 64 hexadecimal digits.
func hashedValue(v string) bool {
	if len(v) != 64 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

// hideIdentifiers is the last step of the tags of a node in a hashed build,
// after the tag filter, which only looked for the node's ID and name: a tag
// whose value holds, in any case, another identifier of the node (its ARN, its
// cloud path, the ID the cloud gives it) has its value hashed, as HashID hashes
// the node's own ARN or path so that the two join; a tag whose key holds one is
// dropped, and not listed, since the list would show it. Without a key it
// changes nothing.
func (b *builder) hideIdentifiers(tags map[string]string, ids ...string) map[string]string {
	if b.key == nil || len(tags) == 0 {
		return tags
	}
	var needles []string
	for _, id := range ids {
		if len(id) >= minIdentifier {
			needles = append(needles, strings.ToLower(id))
		}
	}
	if len(needles) == 0 {
		return tags
	}
	holds := func(s string) bool {
		l := strings.ToLower(s)
		for _, w := range needles {
			if strings.Contains(l, w) {
				return true
			}
		}
		return false
	}
	kept := make(map[string]string, len(tags))
	for k, v := range tags {
		switch {
		case holds(k):
			b.tagsDropped++
		case !hashedValue(v) && holds(v):
			kept[k] = secretscan.HashID(b.key, v)
		default:
			kept[k] = v
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return kept
}

// Shapes of the values that name a thing in a cloud. A tag value of one of
// these shapes is an identifier, whichever resource it names, and a hashed
// snapshot keeps no identifier readable.
var (
	// arnValue finds an ARN anywhere in a value.
	arnValue = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])arn:aws[a-z-]*:`)
	// pathValue finds the start of an Azure resource ID, or of a Google
	// resource name, at the start of a value or after a separator.
	pathValue = regexp.MustCompile(`(?i)(?:^|[\s,;=:"'(])(?:/(?:subscriptions|providers|tenants)/|(?:projects|folders|organizations|billingaccounts)/[a-z0-9])`)
	// accountValue finds a standalone number of 12 digits: an AWS account.
	accountValue = regexp.MustCompile(`(?:^|\D)[0-9]{12}(?:\D|$)`)
	// uuidValue finds a UUID: an Azure subscription, tenant or object.
	uuidValue = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	// cloudIDValue finds a <prefix>-<hex> ID, as AWS writes them (vpc-0abc..,
	// i-0123.., sg-..).
	cloudIDValue = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])([a-z][a-z0-9]{0,11})-([0-9a-f]{8,})(?:[^a-z0-9]|$)`)
	// hostValue finds the host of a cloud's storage or API endpoint.
	hostValue = regexp.MustCompile(`(?i)\.(?:amazonaws\.com|blob\.core\.windows\.net|googleapis\.com)(?:[^a-z0-9]|$)`)
)

// awsIDPrefixes are the prefixes of the IDs AWS writes with a hexadecimal
// part, which are IDs whatever the digits are (vpc-12345678).
var awsIDPrefixes = map[string]bool{
	"vpc": true, "subnet": true, "sg": true, "i": true, "ami": true, "vol": true, "snap": true, "eni": true,
	"igw": true, "nat": true, "rtb": true, "acl": true, "vpce": true, "pcx": true, "tgw": true, "eipalloc": true,
	"eipassoc": true, "lt": true, "fl": true, "vgw": true, "cgw": true, "vpn": true, "dopt": true, "rtbassoc": true,
}

// identifierShaped says a value has the shape of an identifier of a thing in
// a cloud: an ARN, an Azure resource ID or a Google resource name, a
// 12-digit account number, a UUID, a <prefix>-<hex> ID, a URL (a bucket path
// among them) or the host of a cloud endpoint.
func identifierShaped(v string) bool {
	if v == "" || hashedValue(v) {
		return false
	}
	if strings.Contains(v, "://") || arnValue.MatchString(v) || pathValue.MatchString(v) ||
		accountValue.MatchString(v) || uuidValue.MatchString(v) || hostValue.MatchString(v) {
		return true
	}
	for _, m := range cloudIDValue.FindAllStringSubmatch(v, -1) {
		hexPart := m[2]
		if awsIDPrefixes[strings.ToLower(m[1])] || strings.ContainsAny(hexPart, "0123456789") && strings.ContainsAny(strings.ToLower(hexPart), "abcdef") {
			return true
		}
	}
	return false
}

// identifierSet is what the tags of the nodes of a snapshot must not name: the
// places states and inventories were read from, the module paths, and the IDs
// of the nodes.
type identifierSet struct {
	// contained are matched anywhere in a value: they are long and have
	// separators of their own.
	contained []string
	// tokens are matched as a whole value, or as a token of one (split at
	// anything but a letter, a digit, "-", "_" and ".").
	tokens map[string]bool
}

// identifiers collects the identifierSet of the tables, before anything is
// hashed or cleared.
func identifiers(t snapshot.Tables) identifierSet {
	set := identifierSet{tokens: map[string]bool{}}
	seen := map[string]bool{}
	contain := func(v string) {
		l := strings.ToLower(v)
		if len(l) >= minIdentifier && !seen[l] && !hashedValue(v) {
			seen[l] = true
			set.contained = append(set.contained, l)
		}
	}
	token := func(v string) {
		if len(v) >= minIdentifier && !hashedValue(v) {
			set.tokens[strings.ToLower(v)] = true
		}
	}
	for _, s := range t.Sources {
		contain(s.Location)
	}
	for _, n := range t.Nodes {
		contain(n.Module)
		contain(n.Root)
		token(n.NativeID)
		token(n.ARNOrPath)
	}
	sort.Strings(set.contained)
	return set
}

// names says v is, or holds as a token, an identifier of the set, or holds
// one of its places and module paths.
func (s identifierSet) names(v string) bool {
	l := strings.ToLower(v)
	if s.tokens[l] {
		return true
	}
	for _, c := range s.contained {
		if strings.Contains(l, c) {
			return true
		}
	}
	for _, tok := range strings.FieldsFunc(l, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.'
	}) {
		if s.tokens[tok] {
			return true
		}
	}
	return false
}

// hideTagIdentifiers is the last step of the tags of a hashed build, run on
// the tables with everything they name still readable: a tag value of the shape
// of an identifier (see identifierShaped), or that is or holds an identifier
// of the set, has its value hashed with the same hash as the ID it is, so that
// it still joins; a tag whose key has the shape of one is dropped, and not
// listed, since the list would show it.
func (b *builder) hideTagIdentifiers(t snapshot.Tables, set identifierSet) {
	for i, n := range t.Nodes {
		if len(n.Tags) == 0 {
			continue
		}
		kept := make(map[string]string, len(n.Tags))
		for k, v := range n.Tags {
			switch {
			case identifierShaped(k):
				b.tagsDropped++
			case !hashedValue(v) && (identifierShaped(v) || set.names(v)):
				kept[k] = secretscan.HashID(b.key, v)
				b.tagValuesHashed++
			default:
				kept[k] = v
			}
		}
		if len(kept) == 0 {
			kept = nil
		}
		n.Tags = kept
		t.Nodes[i] = n
	}
}
