from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from sangrep_contracts import (
    ContractValidationError,
    CustodyStateV1,
    EvidenceCoverageStateV1,
    EvidenceVersionV1,
    ProjectionRevisionV1,
    SourceObjectKindV1,
    SourceObjectVersionV1,
    StructureRevisionV1,
    canonical_json_sha256,
)


def _source() -> SourceObjectVersionV1:
    return SourceObjectVersionV1(
        source_object_id="source:policy",
        source_version_id="source-version:policy:v1",
        object_kind=SourceObjectKindV1.FILE,
        byte_size=27,
        content_sha256="1" * 64,
        media_type="text/markdown",
        custody_state=CustodyStateV1.EXTERNAL_READ_ONLY,
        provenance=(("adapter", "filesystem-markdown-v1"),),
    )


def _evidence() -> EvidenceVersionV1:
    source = _source()
    return EvidenceVersionV1(
        evidence_version_id="evidence:policy:v1",
        source_version_ids=(source.source_version_id,),
        adapter_profile_id="filesystem-markdown-v1",
        adapter_profile_sha256="2" * 64,
        coverage_state=EvidenceCoverageStateV1.COMPLETE,
        warning_codes=(),
        blocker_codes=(),
        canonical_output_sha256="3" * 64,
    )


def _structure() -> StructureRevisionV1:
    evidence = _evidence()
    return StructureRevisionV1(
        structure_revision_id="structure:policy:v1",
        evidence_version_id=evidence.evidence_version_id,
        structure_profile_id="markdown-headings-v1",
        structure_profile_sha256="4" * 64,
        graph_sha256="5" * 64,
    )


def _projection() -> ProjectionRevisionV1:
    structure = _structure()
    return ProjectionRevisionV1(
        projection_revision_id="projection:reviewer:v1",
        structure_revision_id=structure.structure_revision_id,
        projection_profile_id="reviewer-markdown",
        projection_profile_version="1",
        projection_profile_sha256="6" * 64,
        payload_sha256="7" * 64,
    )


def test_source_object_round_trips_and_is_frozen_and_slotted() -> None:
    source = _source()

    assert SourceObjectVersionV1.from_json_obj(source.to_json_obj()) == source
    assert source.digest == canonical_json_sha256(source.to_json_obj())
    assert len(source.digest) == 64
    assert not hasattr(source, "__dict__")
    with pytest.raises(FrozenInstanceError):
        source.byte_size = 28  # type: ignore[misc]


def test_identity_mutation_changes_digest() -> None:
    source = _source()

    assert replace(source, byte_size=28).digest != source.digest


@pytest.mark.parametrize(
    "change",
    [
        {"content_sha256": "A" * 64},
        {"byte_size": -1},
        {"source_object_id": ""},
        {"media_type": "not a media type"},
        {"provenance": (("duplicate", "a"), ("duplicate", "b"))},
    ],
)
def test_source_object_rejects_invalid_identity(change: dict[str, object]) -> None:
    with pytest.raises(ContractValidationError):
        replace(_source(), **change)  # type: ignore[arg-type]


def test_source_object_rejects_unsafe_integer_byte_size() -> None:
    with pytest.raises(ContractValidationError):
        replace(_source(), byte_size=2**53)


def test_source_object_rejects_non_nfc_provenance_values() -> None:
    with pytest.raises(ContractValidationError, match="NFC"):
        replace(_source(), provenance=(("note", "e\u0301"),))


def test_evidence_rejects_duplicate_source_versions() -> None:
    with pytest.raises(ContractValidationError, match="duplicate"):
        EvidenceVersionV1(
            evidence_version_id="evidence:v1",
            source_version_ids=("source:v1", "source:v1"),
            adapter_profile_id="markdown-v1",
            adapter_profile_sha256="2" * 64,
            coverage_state=EvidenceCoverageStateV1.COMPLETE,
            warning_codes=(),
            blocker_codes=(),
            canonical_output_sha256="3" * 64,
        )


@pytest.mark.parametrize(
    "change",
    [
        {"warning_codes": ("Bad",)},
        {"blocker_codes": ("bad!",)},
    ],
)
def test_evidence_rejects_invalid_code_arrays(change: dict[str, object]) -> None:
    with pytest.raises(ContractValidationError):
        replace(_evidence(), **change)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("factory", "missing_key", "unknown_key"),
    [
        (_source, "sourceVersionId", "unexpected"),
        (_evidence, "canonicalOutputSha256", "unexpected"),
        (_structure, "graphSha256", "unexpected"),
        (_projection, "payloadSha256", "unexpected"),
    ],
)
def test_from_json_rejects_missing_and_unknown_fields(
    factory: object,
    missing_key: str,
    unknown_key: str,
) -> None:
    identity = factory()
    payload = identity.to_json_obj()

    payload_missing = dict(payload)
    payload_missing.pop(missing_key)
    with pytest.raises(ContractValidationError):
        type(identity).from_json_obj(payload_missing)

    payload_unknown = dict(payload)
    payload_unknown[unknown_key] = "value"
    with pytest.raises(ContractValidationError):
        type(identity).from_json_obj(payload_unknown)


def test_from_json_wraps_malformed_identity_values() -> None:
    payload = _source().to_json_obj()
    payload["objectKind"] = "not-a-kind"

    with pytest.raises(ContractValidationError):
        SourceObjectVersionV1.from_json_obj(payload)


def test_to_json_obj_returns_fresh_mutable_values() -> None:
    source = _source()

    first = source.to_json_obj()
    second = source.to_json_obj()
    assert first is not second
    assert first["provenance"] is not second["provenance"]

    first["provenance"]["extra"] = "value"  # type: ignore[index]

    assert SourceObjectVersionV1.from_json_obj(second) == source


def test_complete_identity_chain_round_trips_with_distinct_digests() -> None:
    source = _source()
    evidence = _evidence()
    structure = _structure()
    projection = _projection()

    objects = (source, evidence, structure, projection)
    assert len({item.digest for item in objects}) == 4
    assert SourceObjectVersionV1.from_json_obj(source.to_json_obj()) == source
    assert EvidenceVersionV1.from_json_obj(evidence.to_json_obj()) == evidence
    assert StructureRevisionV1.from_json_obj(structure.to_json_obj()) == structure
    assert ProjectionRevisionV1.from_json_obj(projection.to_json_obj()) == projection
