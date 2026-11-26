// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/IgnatG/infraharvest/pkg/secretscan"
	"github.com/IgnatG/infraharvest/pkg/tfstate"
)

// Backends, as the sources table names them.
const (
	BackendLocal  = "local"
	BackendS3     = "s3"
	BackendGCS    = "gcs"
	BackendAzBlob = "azblob"
	BackendHCP    = "hcp"
)

const redacted = "[redacted]"

// queryKeys are the only query parameters of a location that are kept: the
// ones pkg/tfstate reads. Anything else in a query, such as a token or a
// signature, is dropped, whatever its name.
var queryKeys = map[string]bool{"region": true, "profile": true, "workspace_key_prefix": true, "host": true}

// Resolve turns a location as the user wrote it into one pkg/tfstate reads:
// a path, s3://bucket/prefix, gs://bucket/prefix, azblob://account/container/prefix
// (https://account.blob.core.windows.net/container/prefix, which is also
// accepted as it is) and hcp://organization/workspace (tfc://, also accepted).
func Resolve(location string) (string, error) {
	rest, ok := strings.CutPrefix(location, "azblob://")
	if ok {
		account, tail, _ := strings.Cut(rest, "/")
		if account == "" {
			return "", fmt.Errorf("%s: name an account and a container: azblob://<account>/<container>/<prefix>", Sanitise(location))
		}
		if !strings.Contains(account, ".") {
			account += ".blob.core.windows.net"
		}
		return "https://" + account + "/" + tail, nil
	}
	if rest, ok = strings.CutPrefix(location, "hcp://"); ok {
		return "tfc://" + rest, nil
	}
	return location, nil
}

// BackendOf names the backend a resolved location is read from.
func BackendOf(location string) string {
	switch {
	case strings.HasPrefix(location, "s3://"):
		return BackendS3
	case strings.HasPrefix(location, "gs://"):
		return BackendGCS
	case strings.HasPrefix(location, "tfc://"):
		return BackendHCP
	case strings.HasPrefix(location, "https://"), strings.HasPrefix(location, "http://"):
		return BackendAzBlob
	}
	return BackendLocal
}

// WorkspaceOf returns the Terraform workspace a state's location says it
// is, or "" where the location does not say: the backends keep a workspace
// at a place of their own, and a custom prefix or file name is not told from
// any other.
func WorkspaceOf(location string) string {
	u, err := url.Parse(location)
	if err != nil || !strings.Contains(location, "://") {
		return ""
	}
	key := strings.TrimPrefix(u.Path, "/")
	switch u.Scheme {
	case "s3":
		if rest, ok := strings.CutPrefix(key, "env:/"); ok {
			ws, _, _ := strings.Cut(rest, "/")
			return ws
		}
		return "default"
	case "gs":
		if path.Base(key) == "default.tfstate" {
			return "default"
		}
	case "https":
		if _, ws, ok := strings.Cut(key, ".tfstateenv:"); ok {
			return ws
		}
		if strings.HasSuffix(key, ".tfstate") {
			return "default"
		}
	case "tfc":
		return path.Base(key)
	}
	return ""
}

// Sanitise returns a location that is safe to write down: no user name or
// password, no query parameter other than the few pkg/tfstate reads, and no
// part that has the format of a credential, which is replaced with
// [redacted]. A path or a location that is not a URL is returned as it is
// unless it is a credential itself.
func Sanitise(location string) string {
	if !strings.Contains(location, "://") {
		if secretscan.CredentialFormat(location) != "" {
			return redacted
		}
		return location
	}
	u, err := url.Parse(location)
	if err != nil {
		return redacted
	}
	var b strings.Builder
	b.WriteString(u.Scheme + "://")
	b.WriteString(clean(u.Hostname() + portOf(u)))
	segments := strings.Split(u.Path, "/")
	for i, s := range segments {
		segments[i] = clean(s)
	}
	b.WriteString(strings.Join(segments, "/"))
	var keep []string
	for k, vs := range u.Query() {
		if !queryKeys[k] || len(vs) == 0 {
			continue
		}
		keep = append(keep, k+"="+clean(vs[0]))
	}
	sort.Strings(keep)
	if len(keep) > 0 {
		b.WriteString("?" + strings.Join(keep, "&"))
	}
	return b.String()
}

func portOf(u *url.URL) string {
	if p := u.Port(); p != "" {
		return ":" + p
	}
	return ""
}

// clean replaces a part that is a credential.
func clean(s string) string {
	if secretscan.CredentialFormat(s) != "" {
		return redacted
	}
	return s
}

// Scrub removes credentials from free text, such as the message of an error
// that quotes a URL: any word that has the format of a credential, and any
// URL in it, goes through Sanitise.
func Scrub(s string) string {
	words := strings.Fields(s)
	for i, w := range words {
		trimmed := strings.Trim(w, `"'()[]{}<>,;`)
		switch {
		case strings.Contains(trimmed, "://"):
			words[i] = strings.Replace(w, trimmed, Sanitise(trimmed), 1)
		case secretscan.CredentialFormat(trimmed) != "":
			words[i] = strings.Replace(w, trimmed, redacted, 1)
		}
	}
	return strings.Join(words, " ")
}

// producerKey is the key a state at source is found by, so that a
// terraform_remote_state that reads it is matched to it: the backend and the
// bucket, container or organization, and the object's key or the workspace.
func producerKey(source string) string {
	if !strings.Contains(source, "://") {
		return "local|" + filepath.ToSlash(filepath.Clean(source))
	}
	u, err := url.Parse(source)
	if err != nil {
		return ""
	}
	key := strings.TrimPrefix(u.Path, "/")
	switch u.Scheme {
	case "s3":
		return "s3|" + u.Host + "|" + key
	case "gs":
		return "gcs|" + u.Host + "|" + key
	case "https":
		account, _, _ := strings.Cut(strings.ToLower(u.Hostname()), ".")
		container, blob, _ := strings.Cut(key, "/")
		return "azblob|" + account + "|" + container + "|" + blob
	case "tfc":
		// tfc://org/workspace, or tfc://host/org/workspace for another host.
		parts := strings.Split(key, "/")
		host, org, ws := tfstate.DefaultHCPTerraformHost, u.Host, key
		if len(parts) == 2 {
			host, org, ws = u.Host, parts[0], parts[1]
		}
		return "hcp|" + strings.ToLower(host) + "|" + org + "|" + ws
	}
	return ""
}

// consumerKeys are the keys a terraform_remote_state's configuration can
// name a state by: what the backend writes the workspace's state as. The
// remote state of a local file is matched by what its path ends in.
func consumerKeys(rs tfstate.RemoteState, from string) []string {
	ws := rs.Workspace
	named := ws != "" && ws != "default"
	switch rs.Backend {
	case "s3":
		if rs.Bucket == "" || rs.Key == "" {
			return nil
		}
		key := rs.Key
		if named {
			key = "env:/" + ws + "/" + rs.Key
		}
		return []string{"s3|" + rs.Bucket + "|" + key}
	case "gcs":
		if rs.Bucket == "" {
			return nil
		}
		name := "default"
		if named {
			name = ws
		}
		return []string{"gcs|" + rs.Bucket + "|" + strings.TrimPrefix(path.Join(rs.Key, name+".tfstate"), "/")}
	case "azurerm":
		if rs.Account == "" || rs.Bucket == "" || rs.Key == "" {
			return nil
		}
		key := rs.Key
		if named {
			key += "env:" + ws
		}
		return []string{"azblob|" + strings.ToLower(rs.Account) + "|" + rs.Bucket + "|" + key}
	case "remote":
		if rs.Organization == "" || ws == "" {
			return nil
		}
		host := rs.Host
		if host == "" {
			host = tfstate.DefaultHCPTerraformHost
		}
		return []string{"hcp|" + strings.ToLower(host) + "|" + rs.Organization + "|" + ws}
	case "local":
		if rs.Key == "" {
			return nil
		}
		resolved := localPath(rs.Key, from)
		keys := []string{"local|" + resolved}
		// The path as written is offered too, matched by what a producer path
		// ends in, as before paths were placed: it finds states read from
		// another layout than the one they were written in. A path that climbs
		// out (..) is only matched where it resolves.
		if plain := path.Clean(filepath.ToSlash(rs.Key)); plain != resolved && !strings.HasPrefix(plain, "..") {
			keys = append(keys, "local|"+plain)
		}
		return keys
	}
	return nil
}

// remoteLocation writes where a terraform_remote_state reads from, as a
// location, for the placeholder of a state that is not in the snapshot. ok is
// false where the configuration does not say enough to write one.
func remoteLocation(rs tfstate.RemoteState, from string) (string, bool) {
	ws := rs.Workspace
	named := ws != "" && ws != "default"
	var loc string
	switch rs.Backend {
	case "s3":
		if rs.Bucket == "" || rs.Key == "" {
			return "", false
		}
		key := rs.Key
		if named {
			key = "env:/" + ws + "/" + rs.Key
		}
		loc = "s3://" + rs.Bucket + "/" + key
	case "gcs":
		if rs.Bucket == "" {
			return "", false
		}
		name := "default"
		if named {
			name = ws
		}
		loc = "gs://" + rs.Bucket + "/" + strings.TrimPrefix(path.Join(rs.Key, name+".tfstate"), "/")
	case "azurerm":
		if rs.Account == "" || rs.Bucket == "" || rs.Key == "" {
			return "", false
		}
		key := rs.Key
		if named {
			key += "env:" + ws
		}
		loc = "https://" + strings.ToLower(rs.Account) + ".blob.core.windows.net/" + rs.Bucket + "/" + key
	case "remote":
		if rs.Organization == "" || ws == "" {
			return "", false
		}
		loc = "tfc://" + rs.Organization + "/" + ws
		if rs.Host != "" && rs.Host != tfstate.DefaultHCPTerraformHost {
			loc = "tfc://" + rs.Host + "/" + rs.Organization + "/" + ws
		}
	case "local":
		if rs.Key == "" {
			return "", false
		}
		loc = localPath(rs.Key, from)
	default:
		return "", false
	}
	return Sanitise(loc), true
}

// matches reports whether the state at key is the one consumer names. A
// local path matches when it ends with the consumer's path.
func matches(producer, consumer string) bool {
	if producer == consumer {
		return true
	}
	if rest, ok := strings.CutPrefix(consumer, "local|"); ok && strings.HasPrefix(producer, "local|") {
		p := strings.TrimPrefix(producer, "local|")
		return !strings.HasPrefix(rest, "..") && strings.HasSuffix(p, "/"+rest)
	}
	return false
}

// localPath is the slash path a local terraform_remote_state reads: a
// relative path is taken from the directory of the consumer state, where the
// consumer is a local file, and the result is cleaned. An absolute path is
// only cleaned.
func localPath(key, from string) string {
	k := filepath.ToSlash(key)
	if path.IsAbs(k) || filepath.IsAbs(key) || from == "" || strings.Contains(from, "://") {
		return path.Clean(k)
	}
	return path.Join(path.Dir(filepath.ToSlash(from)), k)
}
