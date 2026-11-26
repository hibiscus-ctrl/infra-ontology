// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/secretscan"
	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

const (
	caseSub = "AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB"
	// The state writes these as the provider returned them, the inventory in
	// the case the live API listed them: they differ only in case.
	stateRG   = "/subscriptions/" + caseSub + "/resourceGroups/Hub-RG"
	invRG     = "/SUBSCRIPTIONS/aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb/resourcegroups/hub-rg"
	stateMG   = "/providers/Microsoft.Management/managementGroups/Platform-MG"
	invMG     = "/providers/microsoft.management/managementgroups/platform-mg"
	caseState = "https://acmestate.blob.core.windows.net/tfstate/case.tfstate"
)

// caseStateRead is a state that manages two Azure resources and two AWS ones
// whose IDs differ from each other only in case.
func caseStateRead(t *testing.T) []Read {
	t.Helper()
	inst := func(typ, name, provider, id string) string {
		return fmt.Sprintf(`{"mode":"managed","type":%q,"name":%q,"provider":"provider[\"registry.terraform.io/hashicorp/%s\"]",`+
			`"instances":[{"schema_version":0,"attributes":{"id":%q}}]}`, typ, name, provider, id)
	}
	doc := `{"version":4,"terraform_version":"1.9.8","serial":1,"lineage":"l","outputs":{},"resources":[` +
		inst("azurerm_resource_group", "hub", "azurerm", stateRG) + "," +
		inst("azurerm_management_group", "platform", "azurerm", stateMG) + "," +
		inst("aws_iam_role", "upper", "aws", "Admin") + "," +
		inst("aws_iam_role", "lower", "aws", "admin") + `]}`
	d, err := tfstate.Parse([]byte(doc), caseState)
	if err != nil {
		t.Fatal(err)
	}
	return []Read{{Location: caseState, Docs: []tfstate.Document{d}}}
}

// caseInventory lists the same resources with the Azure IDs in another case,
// as an inventory that was not hashed or, with key, as one an export hashed in lower case
// (a hash cannot be folded afterwards).
func caseInventory(key []byte) []InventoryRead {
	id := func(s string) string {
		if key != nil {
			return secretscan.Hash(key, strings.ToLower(s))
		}
		return s
	}
	inv := Inventory{
		Location: "case.inventory.json", Schema: SchemaInventory, Tool: "infraharvest", IDsHashed: key != nil,
		Resources: []Resource{
			{Cloud: "azure", Type: "azurerm_resource_group", ID: id(invRG), Status: "unmanaged", Basis: "none"},
			{Cloud: "azure", Type: "azurerm_management_group", ID: id(invMG), Status: "unmanaged", Basis: "none"},
		},
	}
	inv.Digest = digestOf(inv)
	return []InventoryRead{{Location: inv.Location, Inv: inv}}
}

func azureNodes(tb snapshot.Tables) map[string]snapshot.Node {
	m := map[string]snapshot.Node{}
	for _, n := range tb.Nodes {
		if n.Kind == snapshot.KindResource && n.Cloud == "azure" {
			m[n.TFType] = n
		}
	}
	return m
}

// TestAzureIDsOfAnotherCaseAreOneNode: the state and the inventory write the
// same Azure resource ID in different case, in a subscription and outside one;
// each pair is one managed node, with or without --hash-ids, and the node ID
// does not depend on the case. AWS IDs, which are case-sensitive, stay apart.
func TestAzureIDsOfAnotherCaseAreOneNode(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{{"plain", nil}, {"hashed", testKey}} {
		t.Run(tc.name, func(t *testing.T) {
			o := opts
			o.HashKey = tc.key
			joined, err := BuildAll(caseStateRead(t), caseInventory(tc.key), o)
			if err != nil {
				t.Fatal(err)
			}
			stateOnly, err := Build(caseStateRead(t), o)
			if err != nil {
				t.Fatal(err)
			}
			got, want := azureNodes(joined.Tables), azureNodes(stateOnly.Tables)
			if len(got) != 2 || len(want) != 2 {
				t.Fatalf("azure nodes: %d with the inventory, %d without; want 2 each", len(got), len(want))
			}
			for typ, n := range got {
				if n.NodeID != want[typ].NodeID {
					t.Errorf("%s: the inventory's node %s is not the state's %s", typ, n.NodeID, want[typ].NodeID)
				}
				if n.ManagedStatus != snapshot.Managed || n.InventoryType == "" {
					t.Errorf("%s is not the state's managed node joined with the inventory: %+v", typ, n)
				}
			}
			roles := 0
			for _, n := range joined.Tables.Nodes {
				if n.TFType == "aws_iam_role" {
					roles++
				}
			}
			if roles != 2 {
				t.Errorf("%d aws_iam_role nodes, want 2: AWS IDs are case-sensitive", roles)
			}
		})
	}
}
