-- Copyright 2026 Gabriel Ignat
-- SPDX-License-Identifier: AGPL-3.0-only
-- name: unmanaged
-- version: 1
-- description: Resources the live inventory shows that no Terraform state in the snapshot holds. Only as complete as the inventory: a type the inventory did not read is not listed.
-- param: type string - Only this Terraform or inventory type; empty for every type
-- param: account string - Only this account; empty for every account
SELECT account, region, coalesce(nullif(tf_type, ''), inventory_type) AS type, name, arn_or_path, native_id, node_id
FROM nodes
WHERE kind = 'resource' AND managed_status = 'unmanaged'
  AND ({{type}} = '' OR tf_type = {{type}} OR inventory_type = {{type}})
  AND ({{account}} = '' OR account = {{account}})
ORDER BY account, region, type, name, node_id
