# Compatibility and rollback v1

Compatibility uses explicit half-open semantic-version ranges: `minimumInclusive` is admitted and
`maximumExclusive` is rejected. A manifest carries separate ranges for the contracts API, consuming
application, each operating-system/architecture tuple, and rollback.

A consumer must reject a pack when any of the following is true:

- the contracts or application version falls outside its declared range;
- the current operating system or architecture is absent;
- the operating-system version falls outside the selected platform range;
- an exact dependency is absent or a dependency graph contains a cycle;
- the compatibility object does not match its signed digest; or
- rollback selects an artifact whose signing key is unknown, expired, wrong-role, or revoked.

`verify_pack_selection_v1` first authenticates the current manifest against the current trust
registry before consuming its identity, digest, or rollback range. Cached reuse then requires the
exact current version and unsigned-manifest digest. Rollback requires the same pack, family,
publisher, and channel plus a strictly preceding version inside the authenticated current
manifest's rollback range. Both purposes also reverify the candidate signature against the current
trust registry and denylist; historical validity is not current authorization.

Compatibility is necessary but not sufficient for activation. Artifact digests, signature policy,
permissions, conformance verdict, and local safety policy remain independent gates. A compatible
range does not establish product or format support.
