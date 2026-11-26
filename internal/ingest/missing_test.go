// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/IgnatG/infraharvest/pkg/secretscan"
	"github.com/IgnatG/infraharvest/pkg/tfstate"

	"github.com/hibiscus-ctrl/infra-ontology/internal/snapshot"
)

const (
	missAcct   = "111111111111"
	missRegion = "eu-west-1"
	missScope  = "aws/" + missAcct + "/" + missRegion
	missState  = "s3://acme-tfstate/missing.tfstate"
)

func instanceARN(id string) string {
	return fmt.Sprintf("arn:aws:ec2:%s:%s:instance/%s", missRegion, missAcct, id)
}

// missingState manages one EC2 instance per ID and, with azure IDs, one
// Azure virtual network per ID.
func missingState(t *testing.T, instances []string, vnets ...string) []Read {
	t.Helper()
	var res []string
	inst := func(typ, name, provider, id, arn string) string {
		attrs := fmt.Sprintf("%q:%q", "id", id)
		if arn != "" {
			attrs += fmt.Sprintf(",%q:%q", "arn", arn)
		}
		return fmt.Sprintf(`{"mode":"managed","type":%q,"name":%q,"provider":"provider[\"registry.terraform.io/hashicorp/%s\"]",`+
			`"instances":[{"schema_version":0,"attributes":{%s}}]}`, typ, name, provider, attrs)
	}
	for i, id := range instances {
		res = append(res, inst("aws_instance", fmt.Sprintf("i%d", i), "aws", id, instanceARN(id)))
	}
	for i, id := range vnets {
		res = append(res, inst("azurerm_virtual_network", fmt.Sprintf("v%d", i), "azurerm", id, ""))
	}
	doc := `{"version":4,"terraform_version":"1.9.8","serial":1,"lineage":"l","outputs":{},"resources":[` + strings.Join(res, ",") + `]}`
	d, err := tfstate.Parse([]byte(doc), missState)
	if err != nil {
		t.Fatal(err)
	}
	return []Read{{Location: missState, Docs: []tfstate.Document{d}}}
}

// awsListing is an inventory/v1 document that lists the EC2 instances with the
// given IDs in eu-west-1 and counts nothing as failed or skipped.
func awsListing(ids ...string) Inventory {
	inv := Inventory{
		Location: "aws.inventory.json", Schema: SchemaInventory, Tool: "infraharvest",
		Scopes:   []string{missScope},
		Coverage: &Coverage{Scopes: map[string]Counts{missScope: {}}, Types: map[string]Counts{"aws_instance": {}}},
	}
	for _, id := range ids {
		inv.Resources = append(inv.Resources, Resource{
			Cloud: "aws", Account: missAcct, Region: missRegion, Type: "aws_instance", ID: id,
			CloudID: instanceARN(id), Status: "unmanaged", Basis: "none",
		})
	}
	return inv
}

func readsOf(invs ...Inventory) []InventoryRead {
	var reads []InventoryRead
	for _, inv := range invs {
		inv.Digest = digestOf(inv)
		reads = append(reads, InventoryRead{Location: inv.Location, Inv: inv})
	}
	return reads
}

func statusOf(t *testing.T, res Result, typ, id string) string {
	t.Helper()
	return resourceNode(t, res.Tables, typ, id).ManagedStatus
}

func buildMissing(t *testing.T, states []Read, invs []InventoryRead) Result {
	t.Helper()
	res, err := BuildAll(states, invs, opts)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestCompleteListingMarksAStateResourceMissing(t *testing.T) {
	res := buildMissing(t, missingState(t, []string{"i-0001", "i-0002", "i-0003"}), readsOf(awsListing("i-0001", "i-0002")))
	if got := statusOf(t, res, "aws_instance", "i-0003"); got != snapshot.Missing {
		t.Errorf("an instance no complete listing has: %q, want missing", got)
	}
	n := resourceNode(t, res.Tables, "aws_instance", "i-0003")
	if n.Confidence != snapshot.Computed || n.Address == "" {
		t.Errorf("missing node: %+v", n)
	}
	// What the listing has is not missing, and is joined.
	for _, id := range []string{"i-0001", "i-0002"} {
		if got := statusOf(t, res, "aws_instance", id); got != snapshot.Managed {
			t.Errorf("%s is listed live and is %q, want managed", id, got)
		}
	}
	if !strings.Contains(res.Limits, "1 resources in the states read are marked missing") {
		t.Errorf("limits do not count it: %s", res.Limits)
	}
	if err := snapshot.Validate(&res.Tables); err != nil {
		// The nodes must validate with the new status.
		t.Errorf("validate: %v", err)
	}
}

func TestIncompleteListingsMarkNothingMissing(t *testing.T) {
	states := func() []Read { return missingState(t, []string{"i-0001", "i-0002", "i-0003"}) }
	cases := map[string]func(*Inventory){
		"scope has a failed resource":    func(i *Inventory) { i.Coverage.Scopes[missScope] = Counts{Failed: 1} },
		"scope has a skipped resource":   func(i *Inventory) { i.Coverage.Scopes[missScope] = Counts{Skipped: 2} },
		"type has a failed resource":     func(i *Inventory) { i.Coverage.Types["aws_instance"] = Counts{Failed: 1} },
		"type has a skipped resource":    func(i *Inventory) { i.Coverage.Types["aws_instance"] = Counts{Skipped: 1} },
		"the export counts failed ones":  func(i *Inventory) { i.Failed = 3; i.Coverage.Totals.Failed = 3 },
		"totals count failed, no scopes": func(i *Inventory) { i.Coverage.Totals.Failed = 1; i.Coverage.Scopes = nil },
		"totals count skipped, no scope": func(i *Inventory) { i.Coverage.Totals.Skipped = 1; i.Coverage.Scopes = nil },
		"it does not say how complete":   func(i *Inventory) { i.Coverage = nil },
		"an OCSF inventory":              func(i *Inventory) { i.Schema = SchemaOCSFInventory; i.Coverage = nil },
		"another region was listed":      func(i *Inventory) { i.Scopes = []string{"aws/" + missAcct + "/us-east-1"} },
		"another account was listed":     func(i *Inventory) { i.Scopes = []string{"aws/999999999999/" + missRegion} },
		"it does not list the type":      func(i *Inventory) { i.Resources = nil },
		"a resource was left out": func(i *Inventory) {
			i.Resources = append(i.Resources, Resource{Cloud: "aws", Type: "aws_instance", ID: "ghp_" + strings.Repeat("a1B2", 9)})
		},
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			inv := awsListing("i-0001", "i-0002")
			mod(&inv)
			res := buildMissing(t, states(), readsOf(inv))
			for _, id := range []string{"i-0001", "i-0002", "i-0003"} {
				if got := statusOf(t, res, "aws_instance", id); got == snapshot.Missing {
					t.Errorf("%s is missing: the listing was not complete", id)
				}
			}
		})
	}
}

func TestAFailedInventoryMarksNothingMissing(t *testing.T) {
	invs := append(readsOf(awsListing("i-0001", "i-0002")), InventoryRead{Location: "other.inventory.json", Err: errors.New("not JSON")})
	res := buildMissing(t, missingState(t, []string{"i-0001", "i-0002", "i-0003"}), invs)
	if got := statusOf(t, res, "aws_instance", "i-0003"); got != snapshot.Managed {
		t.Errorf("with an inventory that failed to read, i-0003 is %q, want managed: the failed one may list it", got)
	}
	if !strings.Contains(res.Limits, "1 inventories could not be read, so no resource is marked missing") {
		t.Errorf("limits: %s", res.Limits)
	}
}

func TestTypeWhoseIDsDoNotJoinIsNotMissing(t *testing.T) {
	// The listing has instances, but none of them is one the state holds:
	// nothing shows that IDs of the type compare, so nothing is called gone.
	res := buildMissing(t, missingState(t, []string{"i-0001", "i-0002"}), readsOf(awsListing("i-9001", "i-9002")))
	for _, id := range []string{"i-0001", "i-0002"} {
		if got := statusOf(t, res, "aws_instance", id); got != snapshot.Managed {
			t.Errorf("%s is %q, want managed", id, got)
		}
	}
}

func TestAnotherCompleteListingStillSaysMissing(t *testing.T) {
	// A partial listing of the scope does not stop a complete one from saying
	// a resource neither lists is missing; one that lists it makes it joined.
	partial := awsListing("i-0001")
	partial.Location = "a.inventory.json"
	partial.Failed, partial.Coverage.Totals.Failed = 1, 1
	complete := awsListing("i-0001", "i-0002")
	complete.Location = "b.inventory.json"
	res := buildMissing(t, missingState(t, []string{"i-0001", "i-0002", "i-0003"}), readsOf(partial, complete))
	if got := statusOf(t, res, "aws_instance", "i-0003"); got != snapshot.Missing {
		t.Errorf("i-0003 is %q, want missing", got)
	}
	if got := statusOf(t, res, "aws_instance", "i-0002"); got != snapshot.Managed {
		t.Errorf("i-0002 is %q, want managed", got)
	}
}

func TestHashedListingNeedsTheKeyToSayMissing(t *testing.T) {
	states := func() []Read { return missingState(t, []string{"i-0001", "i-0002", "i-0003"}) }
	hashed := func(ids ...string) Inventory {
		inv := awsListing(ids...)
		inv.IDsHashed = true
		for i := range inv.Resources {
			inv.Resources[i].ID = secretscan.Hash(testKey, inv.Resources[i].ID)
			inv.Resources[i].CloudID = secretscan.Hash(testKey, inv.Resources[i].CloudID)
		}
		return inv
	}
	o := opts
	res, err := BuildAll(states(), readsOf(hashed("i-0001", "i-0002")), o)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range res.Tables.Nodes {
		if n.ManagedStatus == snapshot.Missing {
			t.Errorf("%s is missing though the inventory's IDs cannot be compared without the key", n.TFType)
		}
	}
	o.HashKey = testKey
	res, err = BuildAll(states(), readsOf(hashed("i-0001", "i-0002")), o)
	if err != nil {
		t.Fatal(err)
	}
	var missing int
	for _, n := range res.Tables.Nodes {
		if n.ManagedStatus == snapshot.Missing {
			missing++
		}
	}
	if missing != 1 {
		t.Errorf("%d nodes missing with the key, want 1", missing)
	}
}

const (
	vnetSub  = "AAAAAAAA-1111-2222-3333-BBBBBBBBBBBB"
	vnetHub  = "/subscriptions/" + vnetSub + "/resourceGroups/Hub-RG/providers/Microsoft.Network/virtualNetworks/Hub"
	vnetGone = "/subscriptions/" + vnetSub + "/resourceGroups/Hub-RG/providers/Microsoft.Network/virtualNetworks/Gone"
	vnetOff  = "/subscriptions/" + vnetSub + "/resourceGroups/Other-RG/providers/Microsoft.Network/virtualNetworks/Off"
)

func azureListing(ids ...string) Inventory {
	scope := "azure/" + strings.ToLower(vnetSub) + "/global"
	inv := Inventory{
		Location: "azure.inventory.json", Schema: SchemaInventory, Tool: "infraharvest", Scopes: []string{scope},
		Coverage: &Coverage{Scopes: map[string]Counts{scope: {}}, Types: map[string]Counts{"azurerm_virtual_network": {}}},
	}
	for _, id := range ids {
		inv.Resources = append(inv.Resources, Resource{
			Cloud: "azure", Account: strings.ToLower(vnetSub), Type: "azurerm_virtual_network", ID: id, Status: "unmanaged", Basis: "none",
		})
	}
	return inv
}

func TestAzureIDsOfAnotherCaseJoinAndAreNotMissing(t *testing.T) {
	// The listing writes the resource's ID in lower case and the state in
	// the case the provider returned: one resource, not a missing one.
	listed := strings.ToLower(vnetHub)
	res := buildMissing(t, missingState(t, nil, vnetHub, vnetGone, vnetOff), readsOf(azureListing(listed)))
	if got := statusOf(t, res, "azurerm_virtual_network", vnetHub); got != snapshot.Managed {
		t.Errorf("a vnet listed in another case is %q, want managed", got)
	}
	// The same resource group is listed and the vnet is not: gone.
	if got := statusOf(t, res, "azurerm_virtual_network", vnetGone); got != snapshot.Missing {
		t.Errorf("a vnet absent from a group the listing lists is %q, want missing", got)
	}
	// Nothing of this group is listed: the listing may have been of one group.
	if got := statusOf(t, res, "azurerm_virtual_network", vnetOff); got != snapshot.Managed {
		t.Errorf("a vnet in a group the listing does not list is %q, want managed", got)
	}
	if n := resourceNode(t, res.Tables, "azurerm_virtual_network", vnetHub); n.InventoryType == "" {
		t.Errorf("the vnet was not joined: %+v", n)
	}
}
