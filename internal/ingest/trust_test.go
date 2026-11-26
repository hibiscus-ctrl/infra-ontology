// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

const iamRoot = "s3://acme-tfstate/prod/iam.tfstate"

// roleResource is the state of an aws_iam_role in account 111111111111 with
// the given trust policy.
func roleResource(t *testing.T, name, policy string) string {
	t.Helper()
	p, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	return `{"mode":"managed","type":"aws_iam_role","name":"` + name + `","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	 "instances":[{"attributes":{"id":"` + name + `","arn":"arn:aws:iam::111111111111:role/` + name + `","assume_role_policy":` + string(p) + `}}]}`
}

func allow(principal, extra string) string {
	return `{"Sid":"PLANTED-SID","Effect":"Allow","Action":"sts:AssumeRole","Principal":` + principal + extra + `}`
}

func policy(statements ...string) string {
	return `{"Version":"2012-10-17","Statement":[` + strings.Join(statements, ",") + `]}`
}

const plantedCondition = `,"Condition":{"StringEquals":{"sts:ExternalId":"PLANTED-EXTERNAL-ID-9f3a"}}`

// trustReads is a state with a role for each kind of trust policy.
func trustReads(t *testing.T) []Read {
	t.Helper()
	ci := `{"AWS":"arn:aws:iam::111111111111:role/ci"}`
	roles := []string{
		roleResource(t, "ci", policy(allow(`{"Service":"ec2.amazonaws.com"}`, ""))),
		roleResource(t, "app", policy(allow(ci, ""))),
		roleResource(t, "acct", policy(allow(`{"AWS":"arn:aws:iam::111111111111:root"}`, ""))),
		roleResource(t, "acctid", policy(allow(`{"AWS":"333333333333"}`, ""))),
		roleResource(t, "svc", policy(allow(`{"Service":["lambda.amazonaws.com","ecs-tasks.amazonaws.com"]}`, ""))),
		roleResource(t, "open", policy(allow(`"*"`, ""))),
		roleResource(t, "openaws", policy(allow(`{"AWS":"*"}`, ""))),
		roleResource(t, "cond", policy(allow(ci, plantedCondition))),
		roleResource(t, "denied", policy(allow(ci, ""), `{"Effect":"Deny","Action":"sts:AssumeRole","Principal":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}`)),
		roleResource(t, "mixed", policy(allow(ci, plantedCondition), allow(ci, ""))),
		roleResource(t, "partner", policy(allow(`{"AWS":"arn:aws:iam::222222222222:role/partner"}`, ""))),
		roleResource(t, "unknownrole", policy(allow(`{"AWS":"arn:aws:iam::111111111111:role/not-in-state"}`, ""))),
		roleResource(t, "web", policy(`{"Effect":"Allow","Action":"sts:AssumeRoleWithWebIdentity","Principal":{"Federated":"arn:aws:iam::111111111111:oidc-provider/token.example.com"}}`)),
		roleResource(t, "federated", policy(allow(`{"Federated":"arn:aws:iam::111111111111:saml-provider/idp"}`, ""))),
		roleResource(t, "broken", "{not json"),
	}
	state := `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[` + strings.Join(roles, ",") + `]}`
	d, err := tfstate.Parse([]byte(state), iamRoot)
	if err != nil {
		t.Fatal(err)
	}
	return []Read{{Location: iamRoot, Docs: []tfstate.Document{d}}}
}

// canAssume returns the can_assume edges into the role called name, as
// from-node and edge pairs.
func canAssume(t *testing.T, tb snapshot.Tables, name string) []snapshot.Edge {
	t.Helper()
	to := nodeAt(t, tb, iamRoot, "aws_iam_role."+name).NodeID
	var out []snapshot.Edge
	for _, e := range tb.Edges {
		if e.Kind == snapshot.EdgeCanAssume && e.ToID == to {
			out = append(out, e)
		}
	}
	return out
}

func nodeByID(tb snapshot.Tables, id string) snapshot.Node {
	for _, n := range tb.Nodes {
		if n.NodeID == id {
			return n
		}
	}
	return snapshot.Node{}
}

func TestCanAssumeFromTrustPolicies(t *testing.T) {
	res := build(t, trustReads(t))
	tb := res.Tables
	ci := nodeAt(t, tb, iamRoot, "aws_iam_role.ci").NodeID

	one := func(name string) (snapshot.Edge, snapshot.Node) {
		t.Helper()
		es := canAssume(t, tb, name)
		if len(es) != 1 {
			t.Fatalf("%s: %d can_assume edges, want 1: %+v", name, len(es), es)
		}
		return es[0], nodeByID(tb, es[0].FromID)
	}

	// A role that trusts another role of the same account: an edge between
	// the two nodes of the snapshot, computed.
	if e, _ := one("app"); e.FromID != ci || e.Confidence != snapshot.Computed || e.Basis != BasisTrustPolicy {
		t.Errorf("role trusting a role: %+v", e)
	}
	// The account's root principal: the account node, and only inferred.
	if e, from := one("acct"); from.Kind != snapshot.KindAccount || from.Account != "111111111111" ||
		e.Confidence != snapshot.Inferred || e.Basis != BasisTrustAccount {
		t.Errorf("root principal: %+v from %+v", e, from)
	}
	if e, from := one("acctid"); from.Kind != snapshot.KindAccount || from.Account != "333333333333" || e.Basis != BasisTrustAccount {
		t.Errorf("account ID principal: %+v from %+v", e, from)
	}
	// A service principal: a placeholder of the service, computed.
	e, from := one("ci")
	if from.Kind != snapshot.KindExternal || from.InventoryType != "service_principal" || from.NativeID != "ec2.amazonaws.com" ||
		e.Confidence != snapshot.Computed || e.Basis != BasisTrustPolicy {
		t.Errorf("service principal: %+v from %+v", e, from)
	}
	if es := canAssume(t, tb, "svc"); len(es) != 2 {
		t.Errorf("two services: %+v", es)
	}
	// A wildcard: one placeholder for any principal, inferred, never dropped.
	for _, name := range []string{"open", "openaws"} {
		if e, from := one(name); from.InventoryType != "any_principal" || e.Confidence != snapshot.Inferred || e.Basis != BasisTrustWildcard {
			t.Errorf("%s: %+v from %+v", name, e, from)
		}
	}
	// A condition is not evaluated: the edge stays, inferred.
	if e, from := one("cond"); from.NodeID != ci || e.Confidence != snapshot.Inferred || e.Basis != BasisTrustCondition {
		t.Errorf("condition: %+v", e)
	}
	// A Deny statement is not evaluated either.
	if e, _ := one("denied"); e.FromID != ci || e.Confidence != snapshot.Inferred || e.Basis != BasisTrustDeny {
		t.Errorf("deny: %+v", e)
	}
	// An unconditional statement for the same principal wins over a conditional one.
	if e, _ := one("mixed"); e.Confidence != snapshot.Computed {
		t.Errorf("mixed: %+v", e)
	}
	// A role of another account is a placeholder built from the ARN, inferred.
	if e, from := one("partner"); from.Kind != snapshot.KindExternal || from.TFType != "aws_iam_role" || from.Account != "222222222222" ||
		from.ARNOrPath != "arn:aws:iam::222222222222:role/partner" || e.Confidence != snapshot.Inferred || e.Basis != BasisTrustCrossAccount {
		t.Errorf("cross-account: %+v from %+v", e, from)
	}
	// A role of the same account that the snapshot does not hold: a placeholder, computed.
	if e, from := one("unknownrole"); from.Kind != snapshot.KindExternal || e.Confidence != snapshot.Computed {
		t.Errorf("unknown role: %+v from %+v", e, from)
	}
	// Federated principals and web-identity-only statements make no edge, and an
	// unreadable policy neither; the manifest says so.
	for _, name := range []string{"web", "federated", "broken"} {
		if es := canAssume(t, tb, name); len(es) != 0 {
			t.Errorf("%s: %+v", name, es)
		}
	}
	for _, want := range []string{"can_assume edges come only from the trust policies", "1 roles have a trust policy that could not be read", "1 principals of trust policies"} {
		if !strings.Contains(res.Limits, want) {
			t.Errorf("limits lack %q: %s", want, res.Limits)
		}
	}
	if err := snapshot.Validate(&tb); err != nil {
		t.Errorf("the rows are not consistent: %v", err)
	}
}

// A state without roles has no can_assume edge and no limit about them.
func TestNoRolesNoTrustLimits(t *testing.T) {
	res := build(t, fixtureReads(t))
	for _, e := range res.Tables.Edges {
		if e.Kind == snapshot.EdgeCanAssume {
			t.Errorf("edge: %+v", e)
		}
	}
	if strings.Contains(res.Limits, "can_assume") {
		t.Errorf("limits: %s", res.Limits)
	}
}

// Everything the trust edges say about a principal is hashed under a key, and
// no address is kept with --drop-addresses; the policy is never in the rows.
func TestCanAssumeHashedAndDropped(t *testing.T) {
	plain := build(t, trustReads(t))
	const partner = "arn:aws:iam::222222222222:role/partner"
	for name, c := range map[string]struct {
		key  []byte
		drop bool
	}{"plain": {nil, false}, "hashed": {testKey, false}, "dropped": {nil, true}, "both": {testKey, true}} {
		t.Run(name, func(t *testing.T) {
			o := hashedOpts(c.key)
			o.DropAddresses = c.drop
			res, err := Build(trustReads(t), o)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(res)
			text := string(raw)
			for _, planted := range []string{"PLANTED", "ExternalId", "2012-10-17", "sts:AssumeRole", "MultiFactor", "oidc-provider", "saml-provider", "not json"} {
				if strings.Contains(text, planted) {
					t.Errorf("the rows hold %q", planted)
				}
			}
			if got, want := countEdges(res.Tables, snapshot.EdgeCanAssume), countEdges(plain.Tables, snapshot.EdgeCanAssume); got != want {
				t.Errorf("%d can_assume edges, want %d", got, want)
			}
			hashed := c.key != nil
			for _, hidden := range []string{partner, "ec2.amazonaws.com", "not-in-state"} {
				if hashed == strings.Contains(text, hidden) {
					t.Errorf("hashed=%v but %q is in the rows: %v", hashed, hidden, strings.Contains(text, hidden))
				}
			}
			if hashed {
				// The account of a principal stays readable, as every account does.
				found := false
				for _, n := range res.Tables.Nodes {
					found = found || n.Kind == snapshot.KindExternal && n.Account == "222222222222" && len(n.ARNOrPath) == 64
				}
				if !found {
					t.Error("no hashed placeholder of the partner role")
				}
			}
			if c.drop {
				for _, n := range res.Tables.Nodes {
					if n.Address != "" || n.Module != "" {
						t.Errorf("address kept: %+v", n)
					}
				}
			}
		})
	}
	// The same key gives the same edges: a diff joins on them.
	a, b := buildHashed(t, testKey, trustReads(t), nil), buildHashed(t, testKey, trustReads(t), nil)
	if render(a.Tables) != render(b.Tables) {
		t.Error("two hashed builds differ")
	}
}

func countEdges(tb snapshot.Tables, kind string) int {
	n := 0
	for _, e := range tb.Edges {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// dataRole is a data.aws_iam_role of the ARN of the role called name.
func dataRole(name, label string) string {
	return `{"mode":"data","type":"aws_iam_role","name":"` + label + `","provider":"provider[\"registry.terraform.io/hashicorp/aws\"]",
	 "instances":[{"attributes":{"id":"` + name + `","arn":"arn:aws:iam::111111111111:role/` + name + `"}}]}`
}

func stateRead(t *testing.T, root string, resources ...string) Read {
	t.Helper()
	state := `{"version":4,"serial":1,"lineage":"l","terraform_version":"1.9.0","outputs":{},"resources":[` + strings.Join(resources, ",") + `]}`
	d, err := tfstate.Parse([]byte(state), root)
	if err != nil {
		t.Fatal(err)
	}
	return Read{Location: root, Docs: []tfstate.Document{d}}
}

// A data source and a managed role of one ARN: the edge starts at the managed
// one, whatever the order of the maps, and among data sources alone at the
// node with the lowest ID.
func TestTrustPrefersManagedRole(t *testing.T) {
	ci := `{"AWS":"arn:aws:iam::111111111111:role/ci"}`
	for i := 0; i < 40; i++ {
		res := build(t, []Read{stateRead(t, iamRoot,
			dataRole("ci", "a"), dataRole("ci", "z"),
			roleResource(t, "ci", policy(allow(`{"Service":"ec2.amazonaws.com"}`, ""))),
			roleResource(t, "app", policy(allow(ci, ""))))})
		managed := nodeAt(t, res.Tables, iamRoot, "aws_iam_role.ci").NodeID
		es := canAssume(t, res.Tables, "app")
		if len(es) != 1 || es[0].FromID != managed {
			t.Fatalf("run %d: edge from %v, want the managed role %s", i, es, managed)
		}
	}
	// Only data sources: the lowest node ID, every time.
	var first string
	for i := 0; i < 40; i++ {
		res := build(t, []Read{stateRead(t, iamRoot,
			dataRole("ci", "a"), dataRole("ci", "b"), dataRole("ci", "c"),
			roleResource(t, "app", policy(allow(ci, ""))))})
		want := ""
		for _, n := range res.Tables.Nodes {
			if n.Kind == snapshot.KindResource && n.ARNOrPath == "arn:aws:iam::111111111111:role/ci" && (want == "" || n.NodeID < want) {
				want = n.NodeID
			}
		}
		es := canAssume(t, res.Tables, "app")
		if len(es) != 1 || es[0].FromID != want {
			t.Fatalf("run %d: edge from %v, want %s", i, es, want)
		}
		if first == "" {
			first = want
		} else if first != want {
			t.Fatalf("ids changed between runs")
		}
	}
}
