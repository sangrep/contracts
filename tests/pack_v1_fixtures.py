from __future__ import annotations

import base64
import copy
import hashlib
import json


def canonical_subset_sha256(value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parser_manifest_json() -> dict[str, object]:
    compatibility: dict[str, object] = {
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
    compatibility_sha256 = canonical_subset_sha256(compatibility)
    digests = {
        "archiveSha256": "1" * 64,
        "payloadTreeSha256": "2" * 64,
        "sbomSha256": "3" * 64,
        "licenseBundleSha256": "4" * 64,
        "conformanceReceiptSha256": "5" * 64,
        "compatibilityContractSha256": compatibility_sha256,
    }
    unsigned_manifest: dict[str, object] = {
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
        "digests": digests,
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
    manifest_sha256 = canonical_subset_sha256(unsigned_manifest)
    manifest = copy.deepcopy(unsigned_manifest)
    manifest["signature"] = {
        "schemaVersion": 1,
        "kind": "sangrepPackSignature",
        "suite": "Ed25519",
        "role": "packPublisher",
        "keyId": f"ed25519-sha256:{'7' * 64}",
        "unsignedEnvelope": {
            "schemaVersion": 1,
            "kind": "sangrepPackUnsignedEnvelope",
            "packId": "sangrep.text-core",
            "version": "1.0.0-dev.1",
            "family": "parser",
            "publisherId": "sangrep",
            "channel": "development",
            "manifestSha256": manifest_sha256,
            **digests,
        },
        "signatureBase64": base64.b64encode(bytes(64)).decode("ascii"),
    }
    return manifest


def intelligence_manifest_json(*, mode: str = "remote") -> dict[str, object]:
    manifest = parser_manifest_json()
    manifest["packId"] = "sangrep.analysis-core"
    manifest["family"] = "intelligence"
    execution = manifest["execution"]
    assert isinstance(execution, dict)
    execution["mode"] = mode
    execution["isolationProfile"] = {
        "local": "processSandboxV1",
        "remote": "remoteServiceV1",
        "hybrid": "hybridProcessV1",
    }[mode]
    manifest["payload"] = {
        "schemaVersion": 1,
        "kind": "intelligencePack",
        "projectionContract": "explicitProjectionV1",
        "resultContract": "reviewResultV1",
        "receiptContract": "analysisReceiptV1",
        "entrypointId": "parse",
    }
    permissions = manifest["permissions"]
    assert isinstance(permissions, dict)
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
    unsigned_envelope = manifest["signature"]
    assert isinstance(unsigned_envelope, dict)
    envelope = unsigned_envelope["unsignedEnvelope"]
    assert isinstance(envelope, dict)
    envelope["packId"] = manifest["packId"]
    envelope["family"] = manifest["family"]
    unsigned = {key: value for key, value in manifest.items() if key != "signature"}
    envelope["manifestSha256"] = canonical_subset_sha256(unsigned)
    return manifest


def catalog_json(*, cyclic: bool = False) -> dict[str, object]:
    first_dependencies: list[dict[str, str]] = []
    second_dependencies: list[dict[str, str]] = [
        {"packId": "sangrep.text-core", "version": "1.0.0-dev.1"}
    ]
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
                "dependencies": second_dependencies,
            },
        ],
    }
