-- Copyright 2026 Gabriel Ignat
-- SPDX-License-Identifier: AGPL-3.0-only
-- name: inventory
-- version: 1
-- description: The nodes of the snapshot, filtered and in a fixed order, for paging with offset. A filter left empty does not filter.
-- param: type string - Only this Terraform or inventory type
-- param: account string - Only this account
-- param: environment string - Only this environment
-- param: module string - Only this module path and the modules inside it
-- param: address_prefix string - Only addresses that start with this text
-- param: offset int[0..1000000] 0 How many rows to skip, for the next page
SELECT node_id, kind, coalesce(nullif(tf_type, ''), inventory_type) AS type, name, address, module,
  account, region, environment, managed_status, arn_or_path
FROM nodes
WHERE ({{type}} = '' OR tf_type = {{type}} OR inventory_type = {{type}})
  AND ({{account}} = '' OR account = {{account}})
  AND ({{environment}} = '' OR environment = {{environment}})
  AND ({{module}} = '' OR module = {{module}} OR starts_with(module, {{module}} || '.'))
  AND ({{address_prefix}} = '' OR starts_with(address, {{address_prefix}}))
ORDER BY account, environment, type, address, name, node_id
OFFSET {{offset}}
