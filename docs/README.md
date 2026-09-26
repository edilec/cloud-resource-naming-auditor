# Resource naming operator notes

Export an inventory whose `complete:true` assertion covers every resource you intend to audit. This reporter does not enumerate cloud accounts, authenticate exports, reserve names, or read current provider policy. The supported naming profiles and collision scopes are fixed in this release. An unsupported service is incomplete, not a green result. Export environment and owner tags as strings, but do not use personal names or real account IDs in fixtures shared with others.

S3 bucket names are compared within the supplied partition, and Lambda function names within supplied partition/account/region. The scope fields must come from the same trusted export process as the names. Do not edit scope fields merely to silence a collision. Findings point to inventory ordinals without exposing identifying values.
