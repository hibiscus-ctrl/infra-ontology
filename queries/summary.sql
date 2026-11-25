-- Copyright 2026 Gabriel Ignat
-- SPDX-License-Identifier: AGPL-3.0-only
-- name: summary
-- version: 1
-- description: How many nodes of each kind the snapshot holds, by whether Terraform manages them.
SELECT kind, managed_status, count(*) AS nodes
FROM nodes
GROUP BY kind, managed_status
ORDER BY kind, managed_status
