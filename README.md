# Cloud Resource Naming Auditor

`TOOL_ID=cloud-resource-naming-auditor`. Zero-dependency Node 22+ reporter for a complete exported resource inventory and a local environment-marker policy. It supports two explicit AWS naming profiles; unsupported providers or services are incomplete, not assumed valid. It never calls cloud APIs, fetches naming rules, creates resources, or changes tags.

```sh
node bin/cloud-resource-naming-auditor.mjs --root examples/pass --policy policy.json --inventory inventory.json
node bin/cloud-resource-naming-auditor.mjs --root examples/fail --policy policy.json --inventory inventory.json
npm run check
```

The examples exit `0` and `1`. `--help` lists flags; `--human` adds a fixed stderr summary. The library exports `TOOL_ID`, `LIMITS`, `RULE_SEVERITY`, and `auditNames(policy,inventory,{now})` with an injected monotonic clock.

## Input and supported profiles

The policy is `{schemaVersion:"1",complete:true,environments:["dev","prod"]}` with unique, nonempty environment IDs. The inventory is `{schemaVersion:"1",complete:true,resources:[...]}`. Each resource has `provider:"aws"`, `service`, `partition` (`aws`, `aws-cn`, or `aws-us-gov`), a 12-digit `account`, `region`, `name`, and `tags:{environment,owner}`. The environment tag must be approved by the policy; an owner tag must be nonblank. These markers are **tags**, not required substrings of the name. Missing tags in a complete inventory are failures; unusable marker values are incomplete evidence.

Supported `service` values:

- `s3-bucket`: name length 3–63, lowercase ASCII letters/digits/period/hyphen, alphanumeric endpoints, no adjacent periods or period-hyphen adjacency, and not an IPv4-looking name. Duplicate scope is the AWS partition, regardless of account or region.
- `lambda-function`: name length 1–64, ASCII letters/digits/underscore/hyphen. Duplicate scope is partition + account + region. The same Lambda name in different regions is not a collision.

An underscore is legal for this Lambda profile and illegal for this S3 profile. The fixed profiles are deliberately a bounded local subset, not a certification of every current provider reservation or account-level rule. Inventory provenance and actual cloud uniqueness cannot be authenticated offline.

## Report contract and limits

Stdout is one deterministic catalog-v1 JSON report; stderr contains only fixed diagnostics. Findings use `@policy` and `@inventory` logical source roles with source ordinals/JSON pointers, never resource names, tag contents, accounts, regions, or host paths. They sort by `(file,pointer,ruleId)` in UTF-16 code-unit order. `summary.checked` counts resources with supported, usable service/scope fields. Invalid CLI usage or duplicate decoded JSON keys in the policy config exit `2` with empty stdout. Unreadable, non-UTF-8, malformed, duplicate-key inventory, or over-limit input returns incomplete JSON at exit `2`. Completed naming or marker violations exit `1`; a complete clean check exits `0`.

| Rule | Severity | Meaning |
| --- | --- | --- |
| `input-unreadable`, `input-invalid`, `export-incomplete`, `byte-limit`, `record-limit`, `depth-limit`, `time-limit` | warning | Evidence could not be fully evaluated |
| `environment-duplicate`, `resource-invalid`, `unsupported-service` | warning | Policy identity, scope, or service is ambiguous or unsupported |
| `name-invalid`, `name-duplicate`, `environment-missing`, `environment-invalid`, `owner-missing` | error | Complete evidence violates a supported profile or marker policy |

Limits: 262,144 policy bytes, 1,048,576 inventory bytes, 20 environments, 1,000 resources, JSON depth 16, and 5,000 ms evaluation time. Exactly N is accepted; N+1 is incomplete. The CLI resolves real paths of both files and requires them inside the real `--root`; it writes nothing. The direct library trusts caller-supplied objects.
