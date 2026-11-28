// Copyright 2026 Gabriel Ignat
// SPDX-License-Identifier: AGPL-3.0-only

package ingest

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// What a build says when nothing could be read is text for a terminal or a
// log, and with --hash-ids it holds no location and no store error: the
// snapshot's own reason for a failed source is replaced the same way.
func TestNothingReadErrorIsWithheldInAHashedBuild(t *testing.T) {
	failed := []Read{{Location: "s3://secret-bucket-name/private/path.tfstate",
		Err: errors.New("get s3://secret-bucket-name/private/path.tfstate: AccessDenied for arn:aws:iam::111111111111:role/ops")}}
	_, err := BuildAll(failed, nil, hashedOpts(testKey))
	if err == nil {
		t.Fatal("nothing was read, and there is no error")
	}
	for _, leak := range []string{"secret-bucket-name", "private/path", "arn:aws", "AccessDenied"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error holds %q: %v", leak, err)
		}
	}
	if !strings.Contains(err.Error(), Withheld) {
		t.Errorf("the error does not hold the withheld text: %v", err)
	}
	// Without a key the cause stays, scrubbed.
	_, err = BuildAll(failed, nil, opts)
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("a plain build lost the cause: %v", err)
	}
}

func TestReadAllStopsAtTheDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	reads := ReadAll(ctx, []string{"testdata/states/net.tfstate", "testdata/states/app.tfstate"}, Stores())
	for _, r := range reads {
		if r.Err == nil || !errors.Is(r.Err, context.DeadlineExceeded) {
			t.Errorf("%s: read past the deadline: %v", r.Location, r.Err)
		}
	}
}
