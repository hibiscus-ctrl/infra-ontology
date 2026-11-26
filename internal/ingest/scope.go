// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"strings"
)

// cloudOf names the cloud a resource is in, from the provider the state
// records for it (provider["registry.terraform.io/hashicorp/aws"]) or, where
// the state has none, from the prefix of its type.
func cloudOf(provider, typ string) string {
	name := ""
	if i := strings.LastIndex(provider, "/"); i >= 0 {
		name = strings.Trim(provider[i+1:], `"]`)
	}
	if c := cloudByProvider(name); c != "" {
		return c
	}
	prefix, _, _ := strings.Cut(typ, "_")
	return cloudByProvider(prefix)
}

func cloudByProvider(name string) string {
	switch name {
	case "aws":
		return "aws"
	case "azurerm", "azapi", "azuread", "azurestack":
		return "azure"
	case "google", "google-beta":
		return "gcp"
	}
	return ""
}

// scope is where a resource is, as far as its own identifiers say.
type scope struct {
	account, region, path string
	// id is the identifier to use in place of the state's, where it is
	// written in one canonical case (Azure resource IDs are folded to lower
	// case).
	id string
}

// scopeOf reads the account, region and path of a resource from its ARN, its
// ID and its identity, and from nothing else: a resource whose identifiers do
// not say where it is has no account or region.
func scopeOf(cloud, id, arn, identityID string) scope {
	s := scope{id: id}
	switch {
	case foldsCase(cloud, id):
		s.id = strings.ToLower(id)
		s.path = s.id
		s.account = segmentAfter(s.id, "subscriptions")
	case strings.HasPrefix(arn, "arn:"):
		s.path = arn
		parts := strings.SplitN(arn, ":", 6)
		if len(parts) == 6 {
			s.region, s.account = parts[3], parts[4]
		}
	case strings.HasPrefix(id, "arn:"):
		s.path = id
		parts := strings.SplitN(id, ":", 6)
		if len(parts) == 6 {
			s.region, s.account = parts[3], parts[4]
		}
	case cloud == "gcp" && strings.HasPrefix(id, "projects/"):
		s.path = id
		s.account = segmentAfter(id, "projects")
		s.region = firstOf(segmentAfter(id, "regions"), segmentAfter(id, "locations"), zoneRegion(segmentAfter(id, "zones")))
	}
	if cloud == "aws" && (s.account == "" || s.region == "") {
		for _, kv := range strings.Split(identityID, ",") {
			k, v, _ := strings.Cut(kv, "=")
			switch {
			case k == "account_id" && s.account == "":
				s.account = v
			case k == "region" && s.region == "":
				s.region = v
			}
		}
	}
	return s
}

// azureRoots start the resource IDs of Azure: those in a subscription, and
// the ones above it (management groups, tenant-wide role definitions).
var azureRoots = []string{"/subscriptions/", "/providers/", "/tenants/"}

// isAzureID tells an Azure resource ID, which Azure treats without regard to
// case, from other identifiers.
func isAzureID(id string) bool {
	for _, r := range azureRoots {
		if len(id) > len(r) && strings.EqualFold(id[:len(r)], r) {
			return true
		}
	}
	return false
}

// segmentAfter returns the path segment that follows the segment key in a
// slash-separated path, or "".
func segmentAfter(p, key string) string {
	parts := strings.Split(p, "/")
	for i := 0; i+1 < len(parts); i++ {
		if strings.EqualFold(parts[i], key) {
			return parts[i+1]
		}
	}
	return ""
}

// zoneRegion is the region of a Google zone such as europe-west1-b.
func zoneRegion(zone string) string {
	if i := strings.LastIndex(zone, "-"); i > 0 {
		return zone[:i]
	}
	return ""
}

func firstOf(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// foldsCase tells whether id is an Azure resource ID to fold to lower case:
// one that starts like one and belongs to Azure. Other providers' IDs that
// happen to start the same way, such as one under /providers/, keep their
// case: they may tell resources apart by it.
func foldsCase(cloud, id string) bool {
	return cloud == "azure" && isAzureID(id)
}
