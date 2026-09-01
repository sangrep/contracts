# Sangrep contracts

Language-neutral evidence, citation, review, receipt, provider-boundary, and pack contracts with
deterministic conformance vectors.

This repository is the canonical home of the `sangrep-contracts` Python distribution and its JSON
Schemas. The Python package has no runtime dependencies. Version `0.1.0.dev0` is a prerelease
candidate; no product availability or support commitment follows from this repository.

## What is included

- immutable evidence identity, hierarchy, filesystem, locator, selector, and citation types;
- Draft 2020-12 JSON Schemas and positive/negative conformance vectors;
- `SangrepPackManifestV1`, `ParserPackV1`, `IntelligencePackV1`, catalog, compatibility,
  resource, permission, license, and conformance contracts;
- `SangrepPackSignatureV1` with Ed25519, RFC 8785 canonical bytes, strict key IDs, and role-aware
  trust policy; and
- one development-only public verification root in
  [`trust/development-pack-roots-v1.json`](trust/development-pack-roots-v1.json).

The checked-in root cannot authorize a release channel. No production signing authority is
provisioned or implied.

## Local verification

Python 3.11 or newer and [uv](https://docs.astral.sh/uv/) are required.

```bash
uv sync --frozen --extra dev
./scripts/check
```

The repository check runs secret and public-boundary scans, license/provenance and dependency
audits, generated artifact drift checks, documentation links, tests, Ruff, Mypy, and a standalone
wheel smoke.

For a focused contract loop:

```bash
uv run --frozen --extra dev pytest -q tests/test_pack_v1.py tests/test_pack_signing_v1.py
uv run --frozen --extra dev python tools/build_pack_vectors.py --check
```

## Contract map

- [`schemas/`](schemas/) contains the normative JSON Schemas.
- [`src/sangrep_contracts/`](src/sangrep_contracts/) contains dependency-free Python readers and
  validators.
- [`vectors/v1/`](vectors/v1/) contains deterministic positive and malicious negative fixtures.
- [`docs/contracts/pack-manifest-v1.md`](docs/contracts/pack-manifest-v1.md) defines manifest and
  catalog behavior.
- [`docs/contracts/compatibility-v1.md`](docs/contracts/compatibility-v1.md) defines compatibility
  and rollback evaluation.
- [`docs/security/pack-signing-v1.md`](docs/security/pack-signing-v1.md) defines signing, trust,
  rotation, and revocation.
- [`docs/conformance/v1.md`](docs/conformance/v1.md) explains vector and qualification semantics.

## Boundaries

These contracts describe data and verification behavior. They do not implement a parser, model
provider, product UI, pack installer, sandbox, catalog service, or production signing system.
Schema validity and a passing conformance fixture do not establish format support, product
acceptance, a release, or a support commitment.

Read [CONTRIBUTING.md](CONTRIBUTING.md) before proposing changes and use [SECURITY.md](SECURITY.md)
for vulnerability reports. Public origin and attribution information is in [ORIGIN.md](ORIGIN.md)
and [NOTICE](NOTICE).

## License

Licensed under the [Apache License 2.0](LICENSE).
