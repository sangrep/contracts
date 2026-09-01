from __future__ import annotations

from sangrep_contracts import (
    BuildProfileV1,
    PackChannelV1,
    PackConformanceVerdictV1,
    PackFamilyV1,
    SangrepPackCatalogV1,
    SangrepPackManifestV1,
    SangrepPackSignatureV1,
    SangrepPackTrustRootsV1,
    SangrepPackUnsignedEnvelopeV1,
    ed25519_key_id_v1,
    manifest_sha256_v1,
    pack_signature_message_v1,
    verify_pack_signature_v1,
)


def test_pack_v1_public_exports_are_importable() -> None:
    assert SangrepPackManifestV1.__name__ == "SangrepPackManifestV1"
    assert SangrepPackCatalogV1.__name__ == "SangrepPackCatalogV1"
    assert SangrepPackSignatureV1.__name__ == "SangrepPackSignatureV1"
    assert SangrepPackUnsignedEnvelopeV1.__name__ == "SangrepPackUnsignedEnvelopeV1"
    assert SangrepPackTrustRootsV1.__name__ == "SangrepPackTrustRootsV1"
    assert PackFamilyV1.PARSER.value == "parser"
    assert PackChannelV1.DEVELOPMENT.value == "development"
    assert PackConformanceVerdictV1.PASSED.value == "passed"
    assert BuildProfileV1.RELEASE.value == "release"
    assert callable(ed25519_key_id_v1)
    assert callable(manifest_sha256_v1)
    assert callable(pack_signature_message_v1)
    assert callable(verify_pack_signature_v1)
