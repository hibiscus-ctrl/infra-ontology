-- Copyright 2026 Gabriel Ignat
-- SPDX-License-Identifier: AGPL-3.0-only
-- name: blast
-- version: 1
-- description: What depends on a node, directly or through others: what breaks or changes if it does. An edge runs from a dependent to what it needs, so this follows the edges backwards.
-- param: node string required A node id, a Terraform address, an ARN or path, or a native id
-- param: depth int[0..50] 5 How many hops to follow
WITH RECURSIVE targets AS (
  SELECT node_id FROM nodes
  WHERE node_id = {{node}} OR address = {{node}} OR arn_or_path = {{node}} OR native_id = {{node}}
), walk(node_id, depth) AS (
  SELECT node_id, 0 FROM targets
  UNION
  SELECT e.from_id, w.depth + 1 FROM walk w JOIN edges e ON e.to_id = w.node_id WHERE w.depth < {{depth}}
), reached AS (
  SELECT node_id, min(depth) AS depth FROM walk GROUP BY node_id
)
SELECT r.depth, n.kind, n.tf_type, n.address, n.name, n.account, n.region, n.managed_status, n.node_id
FROM reached r JOIN nodes n USING (node_id)
ORDER BY r.depth, n.address, n.name, n.node_id
