# Who can read or write a resource

`infra-ontology snapshot build --iam-lens FILE` adds `can_read` and `can_write` edges from the results of [iam-lens](https://github.com/act-security-labs/iam-lens), a separate tool that evaluates the IAM policies of an AWS estate that [iam-collect](https://github.com/act-security-labs/iam-collect) downloaded. infra-ontology never runs iam-lens, never reads the IAM data and calls no cloud API for this: it reads a file you made, and nothing else. iam-lens is AGPL-3.0 and a separate program; nothing of it is bundled or linked here.

An edge reads from can read, or can write, to: `from` is a principal and `to` is a resource of the snapshot, so "who can reach this bucket" is a walk along the edges into it, as "who can assume this role" is for [`can_assume`](state.md#who-can-assume-a-role).

## Making the file

`iam-lens who-can` prints one JSON document (its `WhoCanResponse`) for one resource, and the document does not say which resource it was asked about. So each output is wrapped with the ARN it was asked about, as `{"resource": ARN, "result": the output}`:

```sh
while read -r arn; do
  iam-lens who-can --resource "$arn" | jq -c --arg r "$arn" '{resource: $r, result: .}'
done < arns.txt > who-can.jsonl

infra-ontology snapshot build \
  --state s3://acme-tfstate/prod/ \
  --iam-lens who-can.jsonl
```

A file holds one wrapped result, an array of them, or several one after another (JSON Lines). `--iam-lens` can be given as many times as you like and needs `--state` or `--inventory`: the edges end at the nodes those read. Without `--actions`, `who-can` checks every action that applies to the resource, which is what gives both `can_read` and `can_write` from one run.

A file that is not in this shape (the raw `who-can` output, for one) is a failed source: the snapshot is partial, exit code 3, and `sources` says so. The snapshot's `limits` says that the file was not read.

## What each entry becomes

Each entry of a result's `allowed` list is a principal, a service, an action and the action's access level, as iam-lens writes them.

| The entry | The edge |
| --- | --- |
| a level of `read` or `list` | `can_read` |
| a level of `write`, `tagging` or `permissions management` | `can_write` |
| any other level, and any `sts` action (assuming a role is [`can_assume`](state.md#who-can-assume-a-role)) | none, counted in `limits` |
| an entry for resource patterns (`allowedPatterns`, which a wildcard resource gives) | none, counted in `limits` |

| The principal | The edge starts at | Confidence and basis |
| --- | --- | --- |
| a role or user the snapshot holds, found by its ARN | that node | `computed`, `iam_lens` |
| a role or user it does not hold | an `external` placeholder built from the ARN, as for a trust policy | `computed`, `iam_lens` |
| a service (`delivery.logs.amazonaws.com`) | an `external` placeholder of type `service_principal` | `computed`, `iam_lens` |
| `anonymous` (unsigned access) | the `external` placeholder of type `any_principal` that `can_assume` uses | `inferred`, `iam_lens_public` |
| an account (`arn:aws:iam::123456789012:root`) | an `account` node | `computed`, `iam_lens` |
| a session, an ARN of another service, a string that is not a principal | none, counted in `limits` | |

An entry that has `conditions`, `ignoredConditions` or depends on the role session's name makes an `inferred` edge (`iam_lens_condition`): the condition is not evaluated here and is not kept, only that there was one. Where several entries, or several files, give the same edge, the strongest confidence wins, and among equals the lowest basis, so the order of the files and entries changes nothing.

The resource must be an ARN of an AWS resource the snapshot holds, concrete (no `*` or `?`), and found by its ARN. A result for a resource the snapshot does not hold, or for a wildcard ARN, makes no edge and no node, and `limits` counts it. A result that says iam-lens found no collected data for an account, organization or principal the resource's policy names (`accountsNotFound` and the like) is counted too: who can reach the resource is then not all it lists.

## What it does not say

An edge says iam-lens judged the principal allowed on the IAM data it was given, when it ran: that data is not in the snapshot and may be older than the rest of it. infra-ontology does not check the judgement, and the file is as trustworthy as the person who made it. A snapshot has no way to tell that a file was not edited.

## Caps

A file is read only up to 32 MiB, 10,000 results and 200,000 entries; a file past one is a failed source, and the rest of the snapshot is built. A snapshot takes at most 100,000 `can_read` and `can_write` edges and 10,000 distinct principals from all its files; what is past the caps is counted in `limits` and left out, in the order of the principals' ARNs, so the same files give the same snapshot.

## What is never in a snapshot

The reader names the members it keeps (`principal`, `service`, `action`, `level`, whether `conditions`, `ignoredConditions`, `dependsOnSessionName` or `allowedPatterns` are there, and whether the not-found lists are empty) and the decoder skips every other member. The conditions' keys and values, the grant details with their policy text, and the not-found principals and accounts are never kept; the service and action names choose the kind of edge, and are not written. The ARNs of the principals and of the resource are the identifiers of nodes, and are hashed with `--hash-ids` like the others; an account outside the estate that a principal names is hashed too, as in a trust policy. With `--hash-ids` the file's location and its digest are hashed, and the reason a file failed is not kept. `--drop-addresses` has nothing to drop from these edges.
