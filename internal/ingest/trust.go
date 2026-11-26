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
	typeServicePrincipal = "service_principal"
	typeAnyPrincipal     = "any_principal"
)

var accountID = regexp.MustCompile(`^[0-9]{12}$`)

// principalRef is where a trust edge starts.
type principalRef struct {
	id, basis, conf string
}

// trustState counts what the trust policies held that no edge could be made
// of, for the manifest's limits.
type trustState struct {
	roles, unreadable, skipped int
	arns                       map[string]string // role and user ARNs of the snapshot, to node IDs
}

// addTrust adds a can_assume edge, from each principal an aws_iam_role's trust
// policy names to the role. It runs after the inventories, so that a role or
// user an inventory lists is found by its ARN. It reads only who the policy
// names and whether a condition or a Deny is there (see tfstate.TrustStatement):
// the policy's text was never kept.
func (b *builder) addTrust(states []*docState) {
	b.trust.arns = map[string]string{}
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
			for _, id := range s.byAddress[in.Address] {
				b.trust.roles++
				b.roleTrust(s, id, in.Trust)
			}
		}
	}
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
			ref, ok := b.principal(s, p, account)
			if !ok {
				b.trust.skipped++
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

// principal finds or makes the node a principal of a trust policy stands for.
// It reports false for a principal that is not turned into an edge: a
// federated or canonical user principal, a unique ID of a deleted principal, a
// session, or an ARN of another service.
func (b *builder) principal(s *docState, p tfstate.TrustPrincipal, roleAccount string) (principalRef, bool) {
	switch {
	case p.Type == "*" || strings.Contains(p.Value, "*"):
		if p.Type != "*" && p.Type != "AWS" {
			return principalRef{}, false
		}
		return principalRef{b.placeholder(s, "", typeAnyPrincipal, "", "*"), BasisTrustWildcard, snapshot.Inferred}, true
	case p.Type == "Service":
		return principalRef{b.placeholder(s, "", typeServicePrincipal, "", p.Value), BasisTrustPolicy, snapshot.Computed}, true
	case p.Type != "AWS":
		return principalRef{}, false
	case accountID.MatchString(p.Value):
		return principalRef{b.accountNode(s, p.Value), BasisTrustAccount, snapshot.Inferred}, true
	case !strings.HasPrefix(p.Value, "arn:"):
		return principalRef{}, false
	}
	parts := strings.SplitN(p.Value, ":", 6)
	if len(parts) != 6 || parts[2] != "iam" || !accountID.MatchString(parts[4]) {
		return principalRef{}, false
	}
	acct, res := parts[4], parts[5]
	switch {
	case res == "root":
		return principalRef{b.accountNode(s, acct), BasisTrustAccount, snapshot.Inferred}, true
	case strings.HasPrefix(res, "role/") || strings.HasPrefix(res, "user/"):
		basis, conf := BasisTrustPolicy, snapshot.Computed
		if roleAccount != "" && acct != roleAccount {
			basis, conf = BasisTrustCrossAccount, snapshot.Inferred
		}
		if id, ok := b.trust.arns[p.Value]; ok {
			return principalRef{id, basis, conf}, true
		}
		typ := "aws_iam_role"
		if strings.HasPrefix(res, "user/") {
			typ = "aws_iam_user"
		}
		return principalRef{b.placeholder(s, acct, "", typ, p.Value), basis, conf}, true
	}
	return principalRef{}, false
}

// placeholder adds an external node for a principal the snapshot holds no
// node for, and returns its ID. Its native ID and ARN are the principal as the
// policy writes it, so with a key they are hashed with the other IDs.
func (b *builder) placeholder(s *docState, account, inventoryType, tfType, native string) string {
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
	id := b.nodeID(snapshot.KindAccount, "aws", account, "", "", account)
	b.addNode(snapshot.Node{
		NodeID: id, Kind: snapshot.KindAccount, Cloud: "aws", Account: account, NativeID: account,
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
		s = append(s, fmt.Sprintf("%d roles have a trust policy that could not be read and have no can_assume edge.", t.unreadable))
	}
	if t.skipped > 0 {
		s = append(s, fmt.Sprintf("%d principals of trust policies (federated providers, canonical users, sessions, unique IDs of deleted principals and ARNs of other services) are not turned into edges.", t.skipped))
	}
	return s
}
