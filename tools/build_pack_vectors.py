from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import cast

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sangrep_contracts import (
    JsonObjectValue,
    JsonValue,
    rfc8785_json_bytes_v1,
    rfc8785_json_sha256_v1,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_OUTPUT = ROOT / "vectors/v1/pack-manifest.json"
SIGNING_OUTPUT = ROOT / "vectors/v1/pack-signing.json"
DOMAIN = b"SANGREP-PACK-SIGNATURE-V1\x00"


def _synthetic_key() -> tuple[Ed25519PrivateKey, bytes, str]:
    seed = hashlib.sha256(b"synthetic sangrep pack signature vector v1").digest()
    signing_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"
    return signing_key, public_key, key_id


def _compatibility() -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "packCompatibility",
        "contracts": {
            "minimumInclusive": "1.0.0",
            "maximumExclusive": "2.0.0",
        },
        "application": {
            "minimumInclusive": "1.0.0",
            "maximumExclusive": "2.0.0",
        },
        "operatingSystems": [
            {
                "name": "macos",
                "architectures": ["arm64", "x86_64"],
                "minimumInclusive": "13.0.0",
                "maximumExclusive": "16.0.0",
            }
        ],
        "rollback": {
            "minimumInclusive": "0.9.0",
            "maximumExclusive": "2.0.0",
        },
    }


def _unsigned_parser_manifest() -> dict[str, object]:
    compatibility = _compatibility()
    return {
        "schemaVersion": 1,
        "kind": "sangrepPackManifest",
        "packId": "sangrep.text-core",
        "version": "1.0.0-dev.1",
        "family": "parser",
        "publisher": {
            "publisherId": "sangrep",
            "trustTier": "firstParty",
        },
        "channel": "development",
        "maturity": "reviewableExperimental",
        "limitations": ["Synthetic conformance fixture only."],
        "formats": {
            "supported": ["text/markdown", "text/plain"],
            "unsupported": ["Encrypted input."],
        },
        "compatibility": compatibility,
        "resources": {
            "schemaVersion": 1,
            "kind": "packResources",
            "compressedSizeBytes": 1024,
            "installedSizeBytes": 2048,
            "expectedPeakMemoryBytes": 4096,
            "workerStartupProfile": "boundedSubprocess",
            "workerStartupTimeoutMs": 5000,
        },
        "execution": {
            "mode": "local",
            "isolationProfile": "processSandboxV1",
            "entrypoints": [
                {
                    "entrypointId": "parse",
                    "relativeExecutablePath": "bin/parser",
                    "protocol": "sangrepPackWorkerV1",
                    "arguments": [],
                }
            ],
        },
        "permissions": {
            "sourceDataClasses": ["documentText"],
            "grants": [
                {
                    "permission": "source.read",
                    "required": True,
                    "reason": "Read bounded source bytes.",
                }
            ],
            "network": None,
            "provider": None,
            "userConsent": "notRequired",
        },
        "dependencies": [],
        "payload": {
            "schemaVersion": 1,
            "kind": "parserPack",
            "maximumInputBytes": 1_048_576,
            "outputContract": "canonicalEvidenceV1",
            "locatorContract": "sourceLocatorV1",
            "entrypointId": "parse",
        },
        "provenance": {
            "kind": "sourceArchive",
            "uri": "https://example.invalid/text-core-1.0.0.tar.gz",
            "revision": "v1.0.0",
            "buildReceiptSha256": "6" * 64,
        },
        "digests": {
            "archiveSha256": "1" * 64,
            "payloadTreeSha256": "2" * 64,
            "sbomSha256": "3" * 64,
            "licenseBundleSha256": "4" * 64,
            "conformanceReceiptSha256": "5" * 64,
            "compatibilityContractSha256": rfc8785_json_sha256_v1(cast(JsonValue, compatibility)),
        },
        "license": {
            "expression": "Apache-2.0",
            "noticePath": "NOTICE",
            "licensePaths": ["LICENSE"],
        },
        "conformance": {
            "schemaVersion": 1,
            "kind": "packConformance",
            "suiteId": "sangrep-pack-conformance",
            "suiteVersion": "1.0.0",
            "verdict": "passed",
            "receiptSha256": "5" * 64,
        },
    }


def _signed_manifest(unsigned: dict[str, object]) -> dict[str, object]:
    signing_key, _, key_id = _synthetic_key()
    manifest = copy.deepcopy(unsigned)
    digests = manifest["digests"]
    publisher = manifest["publisher"]
    assert isinstance(digests, dict)
    assert isinstance(publisher, dict)
    envelope: JsonObjectValue = {
        "schemaVersion": 1,
        "kind": "sangrepPackUnsignedEnvelope",
        "packId": cast(str, manifest["packId"]),
        "version": cast(str, manifest["version"]),
        "family": cast(str, manifest["family"]),
        "publisherId": cast(str, publisher["publisherId"]),
        "channel": cast(str, manifest["channel"]),
        "manifestSha256": rfc8785_json_sha256_v1(cast(JsonValue, manifest)),
        "archiveSha256": cast(str, digests["archiveSha256"]),
        "payloadTreeSha256": cast(str, digests["payloadTreeSha256"]),
        "sbomSha256": cast(str, digests["sbomSha256"]),
        "licenseBundleSha256": cast(str, digests["licenseBundleSha256"]),
        "conformanceReceiptSha256": cast(str, digests["conformanceReceiptSha256"]),
        "compatibilityContractSha256": cast(str, digests["compatibilityContractSha256"]),
    }
    signature = signing_key.sign(DOMAIN + rfc8785_json_bytes_v1(cast(JsonValue, envelope)))
    manifest["signature"] = {
        "schemaVersion": 1,
        "kind": "sangrepPackSignature",
        "suite": "Ed25519",
        "role": "packPublisher",
        "keyId": key_id,
        "unsignedEnvelope": envelope,
        "signatureBase64": base64.b64encode(signature).decode("ascii"),
    }
    return manifest


def _parser_manifest() -> dict[str, object]:
    return _signed_manifest(_unsigned_parser_manifest())


def _intelligence_manifest(*, declare_remote_permissions: bool) -> dict[str, object]:
    unsigned = _unsigned_parser_manifest()
    unsigned["packId"] = "sangrep.analysis-core"
    unsigned["family"] = "intelligence"
    execution = cast(dict[str, object], unsigned["execution"])
    execution["mode"] = "remote"
    execution["isolationProfile"] = "remoteServiceV1"
    unsigned["payload"] = {
        "schemaVersion": 1,
        "kind": "intelligencePack",
        "projectionContract": "explicitProjectionV1",
        "resultContract": "reviewResultV1",
        "receiptContract": "analysisReceiptV1",
        "entrypointId": "parse",
    }
    permissions = cast(dict[str, object], unsigned["permissions"])
    grants = cast(list[dict[str, object]], permissions["grants"])
    if declare_remote_permissions:
        grants.extend(
            [
                {
                    "permission": "network.connect",
                    "required": True,
                    "reason": "Reach the declared synthetic endpoint.",
                },
                {
                    "permission": "provider.invoke",
                    "required": True,
                    "reason": "Invoke the declared synthetic provider.",
                },
            ]
        )
    permissions["network"] = {
        "destinations": ["api.example.invalid"],
        "retention": "none",
        "region": "unspecified",
    }
    permissions["provider"] = {
        "providerId": "synthetic-provider",
        "costModel": "providerPublished",
    }
    permissions["userConsent"] = "required"
    return _signed_manifest(unsigned)


def _catalog(*, cyclic: bool) -> dict[str, object]:
    first_dependencies: list[dict[str, str]] = []
    if cyclic:
        first_dependencies.append({"packId": "sangrep.analysis-core", "version": "1.0.0-dev.1"})
    return {
        "schemaVersion": 1,
        "kind": "sangrepPackCatalog",
        "catalogId": "sangrep-development",
        "version": "1.0.0-dev.1",
        "channel": "development",
        "entries": [
            {
                "packId": "sangrep.text-core",
                "version": "1.0.0-dev.1",
                "family": "parser",
                "manifestUri": "https://example.invalid/text-core/manifest.json",
                "manifestSha256": "8" * 64,
                "archiveUri": "https://example.invalid/text-core/archive.tar.zst",
                "archiveSha256": "1" * 64,
                "dependencies": first_dependencies,
            },
            {
                "packId": "sangrep.analysis-core",
                "version": "1.0.0-dev.1",
                "family": "intelligence",
                "manifestUri": "https://example.invalid/analysis-core/manifest.json",
                "manifestSha256": "9" * 64,
                "archiveUri": "https://example.invalid/analysis-core/archive.tar.zst",
                "archiveSha256": "a" * 64,
                "dependencies": [{"packId": "sangrep.text-core", "version": "1.0.0-dev.1"}],
            },
        ],
    }


def _trust_root(
    public_key: bytes,
    key_id: str,
    *,
    role: str = "packPublisher",
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> dict[str, object]:
    public_key_text = base64.b64encode(public_key).decode("ascii")
    custody_class = "synthetic-test-only"
    receipt = {
        "publicKey": public_key_text,
        "keyId": key_id,
        "custodyClass": custody_class,
    }
    return {
        "keyId": key_id,
        "publicKey": public_key_text,
        "suite": "Ed25519",
        "role": role,
        "publisherId": "sangrep",
        "channels": ["development"],
        "custodyClass": custody_class,
        "receiptDigest": f"sha256:{rfc8785_json_sha256_v1(cast(JsonValue, receipt))}",
        "validFrom": valid_from,
        "validUntil": valid_until,
    }


def _trust_roots(public_key: bytes, key_id: str) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "kind": "sangrepPackTrustRoots",
        "trustPolicyVersion": 1,
        "roots": [_trust_root(public_key, key_id)],
        "rotations": [],
        "revocations": [],
    }


def _manifest_vectors() -> dict[str, object]:
    parser = _parser_manifest()
    non_nfc_unsigned = _unsigned_parser_manifest()
    non_nfc_limitations = cast(list[str], non_nfc_unsigned["limitations"])
    non_nfc_limitations[0] = "Synthetic cafe\u0301 limitation."
    non_nfc_parser = _signed_manifest(non_nfc_unsigned)
    intelligence = _intelligence_manifest(declare_remote_permissions=True)
    catalog = _catalog(cyclic=False)
    actual_digests = {
        "archiveSha256": "f" * 64,
        "payloadTreeSha256": "2" * 64,
        "sbomSha256": "3" * 64,
        "licenseBundleSha256": "4" * 64,
        "conformanceReceiptSha256": "5" * 64,
    }
    unknown = copy.deepcopy(parser)
    unknown["unexpected"] = True
    parent_notice = copy.deepcopy(parser)
    cast(dict[str, object], parent_notice["license"])["noticePath"] = "../NOTICE"
    dot_license = copy.deepcopy(parser)
    cast(dict[str, object], dot_license["license"])["licensePaths"] = ["."]
    undeclared = _intelligence_manifest(declare_remote_permissions=False)
    optional_remote = _intelligence_manifest(declare_remote_permissions=True)
    optional_remote_unsigned = {
        key: value for key, value in optional_remote.items() if key != "signature"
    }
    optional_remote_grants = cast(
        list[dict[str, object]],
        cast(dict[str, object], optional_remote_unsigned["permissions"])["grants"],
    )
    for grant in optional_remote_grants:
        if grant["permission"] in {"network.connect", "provider.invoke"}:
            grant["required"] = False
    optional_remote = _signed_manifest(optional_remote_unsigned)
    optional_parser_unsigned = _unsigned_parser_manifest()
    optional_parser_grants = cast(
        list[dict[str, object]],
        cast(dict[str, object], optional_parser_unsigned["permissions"])["grants"],
    )
    optional_parser_grants[0]["required"] = False
    optional_parser = _signed_manifest(optional_parser_unsigned)
    local_network_unsigned = _unsigned_parser_manifest()
    local_network_grants = cast(
        list[dict[str, object]],
        cast(dict[str, object], local_network_unsigned["permissions"])["grants"],
    )
    local_network_grants.append(
        {
            "permission": "network.connect",
            "required": True,
            "reason": "Contradictory local network grant.",
        }
    )
    local_network = _signed_manifest(local_network_unsigned)
    remote_profile = _intelligence_manifest(declare_remote_permissions=True)
    remote_profile_unsigned = {
        key: value for key, value in remote_profile.items() if key != "signature"
    }
    cast(dict[str, object], remote_profile_unsigned["execution"])["isolationProfile"] = (
        "processSandboxV1"
    )
    remote_profile = _signed_manifest(remote_profile_unsigned)
    overlapping_platform_unsigned = _unsigned_parser_manifest()
    overlapping_platforms = cast(
        list[dict[str, object]],
        cast(dict[str, object], overlapping_platform_unsigned["compatibility"])["operatingSystems"],
    )
    overlapping_platforms.append(
        {
            "name": "macos",
            "architectures": ["arm64"],
            "minimumInclusive": "14.0.0",
            "maximumExclusive": "16.0.0",
        }
    )
    overlapping_digests = cast(dict[str, object], overlapping_platform_unsigned["digests"])
    overlapping_digests["compatibilityContractSha256"] = rfc8785_json_sha256_v1(
        cast(JsonValue, overlapping_platform_unsigned["compatibility"])
    )
    overlapping_order_a = _signed_manifest(overlapping_platform_unsigned)
    overlapping_platforms.reverse()
    overlapping_digests["compatibilityContractSha256"] = rfc8785_json_sha256_v1(
        cast(JsonValue, overlapping_platform_unsigned["compatibility"])
    )
    overlapping_order_b = _signed_manifest(overlapping_platform_unsigned)
    absent_sbom = copy.deepcopy(parser)
    del cast(dict[str, object], absent_sbom["digests"])["sbomSha256"]
    absent_license = copy.deepcopy(parser)
    del absent_license["license"]
    publisher_mismatch = copy.deepcopy(parser)
    cast(dict[str, object], publisher_mismatch["publisher"])["publisherId"] = "other"
    oversized_version = copy.deepcopy(parser)
    oversized_version["version"] = f"{'9' * 129}.0.0"
    oversized_reason_unsigned = _unsigned_parser_manifest()
    oversized_reason_grants = cast(
        list[dict[str, object]],
        cast(dict[str, object], oversized_reason_unsigned["permissions"])["grants"],
    )
    oversized_reason_grants[0]["reason"] = "x" * 513
    oversized_reason = _signed_manifest(oversized_reason_unsigned)
    positives = [
        {"name": "development-parser-pack", "contract": "manifest", "value": parser},
        {
            "name": "development-parser-pack-non-nfc",
            "contract": "manifest",
            "value": non_nfc_parser,
        },
        {"name": "remote-intelligence-pack", "contract": "manifest", "value": intelligence},
        {"name": "development-catalog", "contract": "catalog", "value": catalog},
    ]
    for case in positives:
        case["canonicalSha256"] = rfc8785_json_sha256_v1(cast(JsonValue, case["value"]))
    return {
        "schemaVersion": 1,
        "kind": "sangrepPackManifestVectors",
        "positiveCases": positives,
        "negativeCases": [
            {
                "name": "unknown-field",
                "operation": "schema-manifest",
                "value": unknown,
            },
            {
                "name": "parent-segment-notice-path",
                "operation": "schema-manifest",
                "value": parent_notice,
            },
            {
                "name": "dot-segment-license-path",
                "operation": "schema-manifest",
                "value": dot_license,
            },
            {
                "name": "wrong-archive-digest",
                "operation": "artifact-digests",
                "value": parser,
                "actualDigests": actual_digests,
            },
            {
                "name": "incompatible-application-version",
                "operation": "compatibility",
                "value": parser,
                "environment": {
                    "contractsVersion": "1.4.0",
                    "applicationVersion": "2.0.0",
                    "operatingSystem": "macos",
                    "architecture": "arm64",
                    "operatingSystemVersion": "14.2.0",
                },
            },
            {
                "name": "undeclared-network-permissions",
                "operation": "manifest-runtime",
                "value": undeclared,
            },
            {
                "name": "optional-remote-permissions",
                "operation": "schema-manifest",
                "value": optional_remote,
            },
            {
                "name": "optional-parser-source-read",
                "operation": "schema-manifest",
                "value": optional_parser,
            },
            {
                "name": "local-network-permission",
                "operation": "schema-manifest",
                "value": local_network,
            },
            {
                "name": "remote-isolation-profile-mismatch",
                "operation": "schema-manifest",
                "value": remote_profile,
            },
            {
                "name": "overlapping-platform-range-order-a",
                "operation": "manifest-runtime",
                "value": overlapping_order_a,
            },
            {
                "name": "overlapping-platform-range-order-b",
                "operation": "manifest-runtime",
                "value": overlapping_order_b,
            },
            {
                "name": "dependency-cycle",
                "operation": "catalog-dependencies",
                "value": _catalog(cyclic=True),
            },
            {
                "name": "absent-sbom",
                "operation": "schema-manifest",
                "value": absent_sbom,
            },
            {
                "name": "absent-license",
                "operation": "schema-manifest",
                "value": absent_license,
            },
            {
                "name": "publisher-identity-mismatch",
                "operation": "manifest-runtime",
                "value": publisher_mismatch,
            },
            {
                "name": "oversized-semantic-version",
                "operation": "schema-manifest",
                "value": oversized_version,
            },
            {
                "name": "permission-reason-over-schema-maximum",
                "operation": "schema-manifest",
                "value": oversized_reason,
            },
        ],
    }


def _signing_vectors() -> dict[str, object]:
    manifest = _parser_manifest()
    _, public_key, key_id = _synthetic_key()
    roots = _trust_roots(public_key, key_id)
    signature = cast(dict[str, object], manifest["signature"])
    envelope = cast(dict[str, object], signature["unsignedEnvelope"])
    signature_text = cast(str, signature["signatureBase64"])
    public_key_text = base64.b64encode(public_key).decode("ascii")
    negative_cases: list[dict[str, object]] = [
        {
            "name": "noncanonical-json",
            "operation": "canonical-envelope-bytes",
            "bytesBase64": base64.b64encode(
                json.dumps(envelope, ensure_ascii=False, indent=2).encode("utf-8")
            ).decode("ascii"),
        }
    ]
    oversized_integer = b'{"schemaVersion":' + (b"9" * 5000) + b"}"
    negative_cases.append(
        {
            "name": "oversized-envelope-integer",
            "operation": "canonical-envelope-bytes",
            "bytesBase64": base64.b64encode(oversized_integer).decode("ascii"),
        }
    )
    noncanonical_base64 = copy.deepcopy(signature)
    noncanonical_base64["signatureBase64"] = signature_text.rstrip("=")
    negative_cases.append(
        {
            "name": "noncanonical-base64",
            "operation": "signature-object",
            "signature": noncanonical_base64,
        }
    )
    digest_names = {
        "manifestSha256": "digest-change-manifest",
        "archiveSha256": "digest-change-archive",
        "payloadTreeSha256": "digest-change-payload-tree",
        "sbomSha256": "digest-change-sbom",
        "licenseBundleSha256": "digest-change-license-bundle",
        "conformanceReceiptSha256": "digest-change-conformance-receipt",
        "compatibilityContractSha256": "digest-change-compatibility-contract",
    }
    for field_name, case_name in digest_names.items():
        mutated = copy.deepcopy(envelope)
        mutated[field_name] = "f" * 64 if mutated[field_name] != "f" * 64 else "e" * 64
        negative_cases.append(
            {
                "name": case_name,
                "operation": "crypto-envelope",
                "envelope": mutated,
                "publicKey": public_key_text,
                "signatureBase64": signature_text,
            }
        )
    negative_cases.append(
        {
            "name": "invalid-ed25519-signature",
            "operation": "crypto-envelope",
            "envelope": envelope,
            "publicKey": public_key_text,
            "signatureBase64": base64.b64encode(bytes(64)).decode("ascii"),
        }
    )
    role_roots = copy.deepcopy(roots)
    cast(dict[str, object], cast(list[object], role_roots["roots"])[0])["role"] = "catalog"
    unknown_manifest = copy.deepcopy(manifest)
    cast(dict[str, object], unknown_manifest["signature"])["keyId"] = f"ed25519-sha256:{'f' * 64}"
    revoked_roots = copy.deepcopy(roots)
    revoked_roots["revocations"] = [
        {
            "keyId": key_id,
            "revokedAt": "2026-09-01T00:00:00Z",
            "reason": "Synthetic revocation fixture.",
        }
    ]
    for name, selected_manifest, selected_roots, profile in (
        ("role-confusion", manifest, role_roots, "development"),
        ("development-root-release-build", manifest, roots, "release"),
        ("unknown-root", unknown_manifest, roots, "development"),
        ("revoked-key", manifest, revoked_roots, "development"),
        ("rollback-revoked-artifact", manifest, revoked_roots, "development"),
    ):
        negative_cases.append(
            {
                "name": name,
                "operation": "policy",
                "manifest": selected_manifest,
                "trustRoots": selected_roots,
                "buildProfile": profile,
            }
        )
    authority_expansion = copy.deepcopy(roots)
    authority_expansion["trustPolicyVersion"] = 2
    expanded_root = cast(dict[str, object], cast(list[object], authority_expansion["roots"])[0])
    expanded_root["channels"] = ["release"]
    negative_cases.append(
        {
            "name": "successor-authority-expansion",
            "operation": "trust-successor",
            "previousTrustRoots": roots,
            "currentTrustRoots": authority_expansion,
        }
    )
    second_signing_key = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"synthetic sangrep pack rotation vector v1").digest()
    )
    second_public_key = second_signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    second_key_id = f"ed25519-sha256:{hashlib.sha256(second_public_key).hexdigest()}"
    unbounded = {
        "schemaVersion": 1,
        "kind": "sangrepPackTrustRoots",
        "trustPolicyVersion": 2,
        "roots": [
            _trust_root(
                public_key,
                key_id,
                valid_until="2026-10-01T00:00:00Z",
            ),
            _trust_root(
                second_public_key,
                second_key_id,
                valid_from="2026-09-15T00:00:00Z",
            ),
        ],
        "rotations": [
            {
                "fromKeyId": key_id,
                "toKeyId": second_key_id,
                "overlapStartsAt": "2026-09-15T00:00:00Z",
                "overlapEndsAt": None,
            }
        ],
        "revocations": [],
    }
    negative_cases.append(
        {
            "name": "unbounded-rotation",
            "operation": "trust-registry",
            "trustRoots": unbounded,
        }
    )
    return {
        "schemaVersion": 1,
        "kind": "sangrepPackSigningVectors",
        "positiveCases": [
            {
                "name": "synthetic-development-signature",
                "manifest": manifest,
                "trustRoots": roots,
                "keyId": key_id,
                "unsignedEnvelopeSha256": rfc8785_json_sha256_v1(cast(JsonValue, envelope)),
            }
        ],
        "negativeCases": negative_cases,
    }


def _render(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def _write_or_check(path: Path, content: str, *, check: bool) -> bool:
    if check:
        return path.exists() and path.read_text(encoding="utf-8") == content
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    outputs = (
        (MANIFEST_OUTPUT, _render(_manifest_vectors())),
        (SIGNING_OUTPUT, _render(_signing_vectors())),
    )
    current = all(
        _write_or_check(path, content, check=arguments.check) for path, content in outputs
    )
    if arguments.check and not current:
        print("pack-vector-drift: generated vectors are not current")
        return 1
    if arguments.check:
        print("pack-vector-drift: passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
