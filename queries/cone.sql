-- Copyright 2026 Gabriel Ignat
-- SPDX-License-Identifier: AGPL-3.0-only
-- name: cone
-- version: 2
-- description: What a node needs, directly or through others: its dependency cone. An edge runs from a dependent to what it needs, so this follows the edges forwards. It follows dependency edges only; can_assume, can_read and can_write are access, not dependency, and are walked only with include_access=1. edge_kind is the kind of the edge that reached the node and confidence the weakest confidence along the path to it.
-- param: node string required A node id, a Terraform address, an ARN or path, or a native id
-- param: depth int[0..50] 5 How many hops to follow
-- param: include_access int[0..1] 0 1 to also follow can_assume, can_read and can_write edges
WITH RECURSIVE targets AS (
  SELECT node_id FROM nodes
  WHERE node_id = {{node}} OR address = {{node}} OR arn_or_path = {{node}} OR native_id = {{node}}
), walk(node_id, depth, edge_kind, weak) AS (
  SELECT node_id, 0, CAST(NULL AS VARCHAR), 0 FROM targets
  UNION
  SELECT e.to_id, w.depth + 1, e.kind,
    greatest(w.weak, CASE e.confidence WHEN 'observed' THEN 1 WHEN 'computed' THEN 2 ELSE 3 END)
  FROM walk w JOIN edges e ON e.from_id = w.node_id
  WHERE w.depth < {{depth}} AND ({{include_access}} = 1 OR e.kind NOT IN ('can_assume', 'can_read', 'can_write'))
), nearest AS (
  SELECT node_id, min(depth) AS depth FROM walk GROUP BY node_id
), strongest AS (
  SELECT w.node_id, w.depth, min(w.weak) AS weak
  FROM walk w JOIN nearest USING (node_id, depth) GROUP BY w.node_id, w.depth
), reached AS (
  SELECT s.node_id, s.depth, s.weak, min(w.edge_kind) AS edge_kind
  FROM strongest s JOIN walk w ON w.node_id = s.node_id AND w.depth = s.depth AND w.weak = s.weak
  GROUP BY s.node_id, s.depth, s.weak
)
SELECT r.depth, n.kind, n.tf_type, n.address, n.name, n.account, n.region, n.managed_status, n.node_id,
  r.edge_kind, CASE r.weak WHEN 1 THEN 'observed' WHEN 2 THEN 'computed' WHEN 3 THEN 'inferred' END AS confidence
FROM reached r JOIN nodes n USING (node_id)
ORDER BY r.depth, n.address, n.name, n.node_id
