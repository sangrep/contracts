# Contributor and agent guide

## Purpose

This repository owns the Contracts component: Language-neutral evidence, review, and pack contracts with conformance vectors.

## Public information boundary

Assume every branch, commit, Issue, pull request, review, workflow log, artifact, document, and
agent instruction can become permanently public. Work only from repository-local public context.
Do not mention private repositories, parents, roadmaps, task identifiers, worktrees, local paths,
provider records, customer material, credentials, or unreleased product composition.

## Working agreement

1. Read README.md, CONTRIBUTING.md, SECURITY.md, and the assigned public Issue.
2. Keep changes focused and repository-local; consume other components only as released artifacts.
3. Do not add source copied from another repository without reviewed public provenance.
4. Do not hand-edit generated files; run their checked-in generator and drift check.
5. Run `uv sync --frozen --extra dev`, then `./scripts/check`, before pushing or requesting review.
6. Record exact tested and untested scope. Do not claim support or release from a passing build.
7. Use a private security report for vulnerabilities.

## Repository map

- `src/sangrep_contracts/` — dependency-free Python readers and validators.
- `schemas/`, `vectors/`, and `trust/` — normative language-neutral contracts and public roots.
- `tools/` — deterministic generators; generated outputs carry drift checks.
- `tests/` — round-trip, malicious-vector, boundary, and package acceptance.
- `docs/` — contract, compatibility, signing, and conformance explanations.
- `.github/` and `scripts/` — contribution policy, scoped CI, and hard repository checks.

## Dependency direction

No editable installs, submodules, source-tree imports, or hidden cross-repository credentials. Use
versioned artifacts with digests and compatibility declarations.

## Documentation

Implementation facts stay beside this component. User-facing product behavior belongs in its
canonical product documentation. Internal decision history does not enter this repository.

Normative field behavior belongs in schemas and tests. Explanatory changes update the matching page
under `docs/` and keep README links valid. Generated bindings and vectors are never edited by hand.
