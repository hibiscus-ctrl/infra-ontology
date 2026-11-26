// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

// Edge bases written for can_assume. Each says why the edge has its
// confidence: trust_policy is the one a snapshot can state without a caveat.
const (
	// BasisTrustPolicy: the role's trust policy names the principal, with
	// no condition, in the role's own account (or it names a service).
	BasisTrustPolicy = "trust_policy"
	// BasisTrustCrossAccount: it names a role or user of another account,
	// which also needs an identity policy there that this snapshot does not read.
	BasisTrustCrossAccount = "trust_policy_cross_account"
	// BasisTrustAccount: it names an account, so any principal in it whose
	// own policies allow sts:AssumeRole can.
	BasisTrustAccount = "trust_policy_account"
	// BasisTrustCondition: the statement has a condition, which is not evaluated.
	BasisTrustCondition = "trust_policy_condition"
	// BasisTrustDeny: the policy also has a Deny statement, which is not evaluated.
	BasisTrustDeny = "trust_policy_deny"
	// BasisTrustWildcard: the statement names every principal (or every one
	// but those it lists).
	BasisTrustWildcard = "trust_policy_wildcard"
)

// Types of the placeholder nodes the trust edges start at, where the
// principal is not a resource of the snapshot.
const (
	typeServicePrincipal  = "service_principal"
	typeAnyPrincipal      = "any_principal"
	typeWildcardPrincipal = "wildcard_principal"
)

var accountID = regexp.MustCompile(`^[0-9]{12}$`)

// principalRef is where a trust edge starts.
type principalRef struct {
	id, basis, conf string
}

// trustState counts what the trust policies held that no edge could be made
// of, for the manifest's limits.
type trustState struct {
	roles, unreadable, skipped, rejected int
	arns                                 map[string]string // role and user ARNs of the snapshot, to node IDs
	own                                  map[string]bool   // accounts of the resources and accounts the snapshot holds
}

// addTrust adds a can_assume edge, from each principal an aws_iam_role's trust
// policy names to the role. It runs after the inventories, so that a role or
// user an inventory lists is found by its ARN. It reads only who the policy
// names and whether a condition or a Deny is there (see tfstate.TrustStatement):
// the policy's text was never kept.
func (b *builder) addTrust(states []*docState) {
	b.trust.arns = map[string]string{}
	b.trust.own = map[string]bool{}
	for _, n := range b.nodes {
		if n.Account != "" && (n.Kind == snapshot.KindResource || n.Kind == snapshot.KindAccount) {
			b.trust.own[n.Account] = true
		}
	}
	for id, n := range b.nodes {
		if n.Kind == snapshot.KindResource && n.Cloud == "aws" && n.ARNOrPath != "" &&
			(n.TFType == "aws_iam_role" || n.TFType == "aws_iam_user") && !b.preHashed[id+"\x00arn_or_path"] {
			// A thing a state manages beats a data source or an inventory
			// listing of the same ARN; among equals the lowest ID wins, so
			// the edges do not depend on the order of the map.
			if old, ok := b.trust.arns[n.ARNOrPath]; ok {
				if o := b.nodes[old]; arnRank(o) < arnRank(n) || arnRank(o) == arnRank(n) && old < id {
					continue
				}
			}
			b.trust.arns[n.ARNOrPath] = id
		}
	}
	for _, s := range states {
		for _, in := range s.doc.Instances {
			if in.Mode != "managed" || in.Type != "aws_iam_role" {
				continue
			}
			if in.TrustUnreadable {
				b.trust.unreadable++
				continue
			}
			if len(in.Trust) == 0 {
				continue
			}
			if distinctPrincipals(in.Trust) > maxTrustPrincipals {
				// A policy this long is not one a person wrote: no edges, so that
				// it cannot make millions of nodes.
				b.trust.unreadable++
				continue
			}
			for _, id := range s.byAddress[in.Address] {
				b.trust.roles++
				b.roleTrust(s, id, in.Trust)
			}
		}
	}
}

// maxTrustPrincipals is the most distinct principals one role's trust policy
// may name for its edges to be made; infraharvest caps the same.
const maxTrustPrincipals = 500

// distinctPrincipals counts the distinct principals the statements name, and
// stops counting past the cap.
func distinctPrincipals(stmts []tfstate.TrustStatement) int {
	seen := map[tfstate.TrustPrincipal]struct{}{}
	for _, st := range stmts {
		for _, p := range st.Principals {
			seen[p] = struct{}{}
			if len(seen) > maxTrustPrincipals {
				return len(seen)
			}
		}
	}
	return len(seen)
}

// arnRank orders the nodes of one ARN: 0 for one a state manages (or did, and
// an inventory no longer lists), 1 for a data source or an inventory's own.
func arnRank(n snapshot.Node) int {
	if n.ManagedStatus == snapshot.Managed || n.ManagedStatus == snapshot.Missing {
		return 0
	}
	return 1
}

// roleTrust adds the edges of one role's trust statements.
func (b *builder) roleTrust(s *docState, role string, stmts []tfstate.TrustStatement) {
	account := b.nodes[role].Account
	denied := false
	for _, st := range stmts {
		denied = denied || strings.EqualFold(st.Effect, "deny")
	}
	for _, st := range stmts {
		if !strings.EqualFold(st.Effect, "allow") || !st.Assumes {
			continue
		}
		principals := st.Principals
		if st.NotPrincipal {
			// Everyone but the ones listed: read as everyone.
			principals = []tfstate.TrustPrincipal{{Type: "*", Value: "*"}}
		}
		for _, p := range principals {
			ref, outcome := b.principal(s, p, account)
			if outcome != principalEdge {
				if outcome == principalRejected {
					b.trust.rejected++
				} else {
					b.trust.skipped++
				}
				continue
			}
			basis, conf := ref.basis, ref.conf
			switch {
			case basis == BasisTrustWildcard:
			case st.Conditional:
				basis, conf = BasisTrustCondition, snapshot.Inferred
			case denied:
				basis, conf = BasisTrustDeny, snapshot.Inferred
			}
			b.addEdge(snapshot.EdgeCanAssume, basis, conf, ref.id, role, s.source)
		}
	}
}

// What principal makes of a principal of a trust policy.
const (
	principalEdge     = iota // an edge starts at the node
	principalSkipped         // a kind of principal that is not turned into an edge
	principalRejected        // a value that is not the shape its type has, never written
)

// maxPrincipalLen is the longest principal value read: an ARN is 2048 at most.
const maxPrincipalLen = 2048

// servicePrincipal is the shape of a service principal: a service name (and a
// region, for the regional ones) under the domain of a partition of AWS. A
// value of any other shape is not written: it could be anything somebody put
// in a policy.
var servicePrincipal = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*(\.[a-z0-9-]+)*\.(amazonaws\.com(\.cn)?|c2s\.ic\.gov|sc2s\.sgov\.gov)$`)

// principal finds or makes the node a principal of a trust policy stands for.
// It reports principalSkipped for a principal that is not turned into an edge
// (a federated or canonical user principal, a unique ID of a deleted
// principal, a session, or an ARN of another service) and principalRejected
// for a service that is not named as a service is, or a bare string that is
// not "*".
func (b *builder) principal(s *docState, p tfstate.TrustPrincipal, roleAccount string) (principalRef, int) {
	if len(p.Value) > maxPrincipalLen {
		return principalRef{}, principalRejected
	}
	switch {
	case p.Type == "*":
		// A bare string: only "*" is one.
		if p.Value != "*" {
			return principalRef{}, principalRejected
		}
		return principalRef{b.placeholder(s, "", typeAnyPrincipal, "", "*"), BasisTrustWildcard, snapshot.Inferred}, principalEdge
	case p.Type == "Service":
		if !servicePrincipal.MatchString(strings.ToLower(p.Value)) {
			return principalRef{}, principalRejected
		}
		return principalRef{b.placeholder(s, "", typeServicePrincipal, "", p.Value), BasisTrustPolicy, snapshot.Computed}, principalEdge
	case p.Type != "AWS":
		return principalRef{}, principalSkipped
	case p.Value == "*":
		return principalRef{b.placeholder(s, "", typeAnyPrincipal, "", "*"), BasisTrustWildcard, snapshot.Inferred}, principalEdge
	case strings.Contains(p.Value, "*"):
		// A wildcard ARN names a set of principals, each its own: one
		// placeholder for each pattern, so that two patterns do not merge.
		parts := strings.SplitN(p.Value, ":", 6)
		if len(parts) != 6 || parts[0] != "arn" || parts[2] != "iam" {
			return principalRef{}, principalSkipped
		}
		acct := ""
		if accountID.MatchString(parts[4]) {
			acct = parts[4]
		}
		return principalRef{b.placeholder(s, acct, typeWildcardPrincipal, "", p.Value), BasisTrustWildcard, snapshot.Inferred}, principalEdge
	case accountID.MatchString(p.Value):
		return principalRef{b.accountNode(s, p.Value), BasisTrustAccount, snapshot.Inferred}, principalEdge
	case !strings.HasPrefix(p.Value, "arn:"):
		return principalRef{}, principalSkipped
	}
	parts := strings.SplitN(p.Value, ":", 6)
	if len(parts) != 6 || parts[2] != "iam" || !accountID.MatchString(parts[4]) {
		return principalRef{}, principalSkipped
	}
	acct, res := parts[4], parts[5]
	switch {
	case res == "root":
		return principalRef{b.accountNode(s, acct), BasisTrustAccount, snapshot.Inferred}, principalEdge
	case strings.HasPrefix(res, "role/") || strings.HasPrefix(res, "user/"):
		basis, conf := BasisTrustPolicy, snapshot.Computed
		switch {
		case roleAccount == "":
			// The role's account is not known, so the principal may be of another.
			conf = snapshot.Inferred
		case acct != roleAccount:
			basis, conf = BasisTrustCrossAccount, snapshot.Inferred
		}
		if id, ok := b.trust.arns[p.Value]; ok {
			return principalRef{id, basis, conf}, principalEdge
		}
		typ := "aws_iam_role"
		if strings.HasPrefix(res, "user/") {
			typ = "aws_iam_user"
		}
		return principalRef{b.placeholder(s, acct, "", typ, p.Value), basis, conf}, principalEdge
	}
	return principalRef{}, principalSkipped
}

// shown is the account of a principal, as its node says it. The accounts of the
// estate are readable in a hashed snapshot, as for every node; another account,
// one a policy names as a partner or a vendor, is hashed with the key, so that
// the nodes of one account still group.
func (b *builder) shown(account string) string {
	if b.key == nil || account == "" || b.trust.own[account] {
		return account
	}
	return b.h(account)
}

// placeholder adds an external node for a principal the snapshot holds no
// node for, and returns its ID. Its native ID and ARN are the principal as the
// policy writes it, so with a key they are hashed with the other IDs.
func (b *builder) placeholder(s *docState, account, inventoryType, tfType, native string) string {
	account = b.shown(account)
	id := b.nodeID(snapshot.KindExternal, "aws", account, "", firstOf(tfType, inventoryType), native)
	n := snapshot.Node{
		NodeID: id, Kind: snapshot.KindExternal, Cloud: "aws", Account: account, TFType: tfType,
		InventoryType: inventoryType, NativeID: native, Name: native,
		ManagedStatus: snapshot.Unknown, Confidence: snapshot.Inferred, SourceID: s.source,
	}
	if strings.HasPrefix(native, "arn:") {
		n.ARNOrPath = native
	}
	b.addNode(n)
	return id
}

// accountNode adds the node of an AWS account a trust policy names, and
// returns its ID.
func (b *builder) accountNode(s *docState, account string) string {
	native := account
	account = b.shown(account)
	id := b.nodeID(snapshot.KindAccount, "aws", account, "", "", native)
	b.addNode(snapshot.Node{
		NodeID: id, Kind: snapshot.KindAccount, Cloud: "aws", Account: account, NativeID: native,
		ManagedStatus: snapshot.Unknown, Confidence: snapshot.Computed, SourceID: s.source,
	})
	return id
}

// trustLimits is what the can_assume edges leave out, for the manifest.
func (b *builder) trustLimits() []string {
	t := b.trust
	if t.roles == 0 && t.unreadable == 0 {
		return nil
	}
	s := []string{"can_assume edges come only from the trust policies of the aws_iam_role resources a state holds: a role made outside Terraform has none, and identity policies, permission boundaries, service control policies and session policies are not read, so an edge says a trust policy allows it, not that the principal can. An account, a wildcard, a condition, a Deny statement or another account makes an edge inferred, and no condition or Deny is evaluated."}
	if t.unreadable > 0 {
		s = append(s, fmt.Sprintf("%d roles have a trust policy that could not be read, or that names more than %d principals, and have no can_assume edge.", t.unreadable, maxTrustPrincipals))
	}
	if t.rejected > 0 {
		s = append(s, fmt.Sprintf("%d principals of trust policies are not of the form their type has (a service that is not a service name, a string that is not \"*\") and are not kept.", t.rejected))
	}
	if t.skipped > 0 {
		s = append(s, fmt.Sprintf("%d principals of trust policies (federated providers, canonical users, sessions, unique IDs of deleted principals and ARNs of other services) are not turned into edges.", t.skipped))
	}
	return s
}
