# Pack manifest v1

`SangrepPackManifestV1` is the closed, signed description of one installable capability. Unknown
fields are rejected. Every dependency names one exact pack version; catalogs with missing targets,
duplicate identities, or dependency cycles are invalid.

## Required identity and evidence

A manifest declares its pack ID, semantic version, family, publisher, channel, trust tier, maturity,
limitations, supported media types, and explicitly unsupported cases. The two v1 payload families
are:

- `ParserPackV1`, which accepts bounded source bytes and emits canonical evidence and locators; and
- `IntelligencePackV1`, which consumes an explicit projection and emits contract-shaped results and
  receipts.

Defining a family does not enable installation or make a support claim.

The manifest also binds compatibility, resource budgets, execution entrypoints, isolation profile,
source-data classes, permissions, network destinations, provider identity, region, retention, cost
model, consent, provenance, license expression, SBOM, conformance receipt, and rollback range.
Remote and hybrid execution must declare `network.connect` and `provider.invoke`, plus non-null
network/provider policy and required consent. Those grants must be marked required. Local, remote,
and hybrid modes bind respectively to `processSandboxV1`, `remoteServiceV1`, and
`hybridProcessV1`; local mode cannot request network or provider authority. Parser packs are local
in v1 and must declare required `source.read`.

Pack-owned entrypoint, NOTICE, and license paths are relative labels below the pack root. Empty,
absolute, URI-like, dot, parent, repeated-separator, backslash, and control-character paths are
rejected.

## Digest closure

The signed envelope binds lowercase SHA-256 values for:

- the unsigned manifest;
- the archive and payload tree;
- the SBOM and license bundle;
- the conformance receipt; and
- the canonical compatibility contract.

Consumers compare artifact bytes and derived trees to those values before activation. Starting an
executable is not conformance and cannot change a non-passing qualification verdict into support.

Semantic versions are bounded to 128 bytes and safe numeric components. Compatibility has at most
one range for each operating-system/architecture tuple, so reversing the signed array cannot change
the verdict.

## Catalog boundary

`SangrepPackCatalogV1` points to exact manifest and archive digests and repeats exact dependencies
for cycle detection before download. A catalog may select a key already present in the embedded
trust registry; it cannot carry or add a trust root. Catalog and pack-publisher signing roles are
distinct.

The normative schema is
[`schemas/sangrep-pack-manifest-v1.json`](../../schemas/sangrep-pack-manifest-v1.json). Canonical
examples and malicious cases are in
[`vectors/v1/pack-manifest.json`](../../vectors/v1/pack-manifest.json).
