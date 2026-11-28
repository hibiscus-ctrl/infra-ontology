// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"regexp"
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
	s.account, s.region = validAccount(cloud, s.account), validRegion(cloud, s.region)
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

// The shapes of the accounts and regions each cloud writes. An account or a
// region is cut from an ID, an ARN or an identity, and only a value of one of
// these shapes is kept: the text of an ID that is not what it says it is must
// not reach a column that is written as it is and left readable by hashing.
var (
	awsAccountShape  = regexp.MustCompile(`^[0-9]{12}$`)
	uuidShape        = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	gcpProjectShape  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpProjectNumber = regexp.MustCompile(`^[0-9]{6,20}$`)
	awsRegionShape   = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+){1,2}-[0-9]{1,2}$`)
	azureRegionShape = regexp.MustCompile(`^[a-z][a-z0-9]{2,30}$`)
	gcpRegionShape   = regexp.MustCompile(`^(?:[a-z]+-[a-z]+[0-9]+|us|eu|asia|global)$`)
)

// validAccount returns a if it has the shape of an account of the cloud (a
// 12-digit AWS account, an Azure subscription's UUID, a Google project ID or
// number), or of any cloud where the cloud is not known, and "" otherwise.
func validAccount(cloud, a string) string {
	ok := false
	switch cloud {
	case "aws":
		ok = awsAccountShape.MatchString(a)
	case "azure":
		ok = uuidShape.MatchString(a)
	case "gcp":
		ok = gcpProjectShape.MatchString(a) || gcpProjectNumber.MatchString(a)
	default:
		ok = awsAccountShape.MatchString(a) || uuidShape.MatchString(a) || gcpProjectShape.MatchString(a)
	}
	if !ok {
		return ""
	}
	return a
}

// validRegion returns r if it has the shape of a region of the cloud, or of
// any cloud where the cloud is not known, and "" otherwise.
func validRegion(cloud, r string) string {
	ok := false
	switch cloud {
	case "aws":
		ok = awsRegionShape.MatchString(r)
	case "azure":
		ok = azureRegionShape.MatchString(r)
	case "gcp":
		ok = gcpRegionShape.MatchString(r)
	default:
		ok = awsRegionShape.MatchString(r) || azureRegionShape.MatchString(r) || gcpRegionShape.MatchString(r)
	}
	if !ok {
		return ""
	}
	return r
}
