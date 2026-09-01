from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from sangrep_contracts import (
    CitableStateV1,
    CitationAddressV1,
    ContainmentKindV1,
    EvidenceNodeKindV1,
    EvidenceNodeV1,
    EvidenceVersionV1,
    FilesystemEntryKindV1,
    FilesystemEntryStatusV1,
    FilesystemInventoryEntryV1,
    FilesystemSnapshotV1,
    ProjectedNodeV1,
    ProjectionRevisionV1,
    SourceObjectVersionV1,
    StructureRevisionV1,
    TextEncodingProfileV1,
    canonical_json_sha256,
    source_locator_from_json_obj,
)

ROOT = Path(__file__).resolve().parents[1]


IDENTITY_READERS = {
    "sourceObjectVersion": SourceObjectVersionV1.from_json_obj,
    "evidenceVersion": EvidenceVersionV1.from_json_obj,
    "structureRevision": StructureRevisionV1.from_json_obj,
    "projectionRevision": ProjectionRevisionV1.from_json_obj,
}

HIERARCHY_READERS = {
    "filesystemInventoryEntry": FilesystemInventoryEntryV1.from_json_obj,
    "filesystemSnapshot": FilesystemSnapshotV1.from_json_obj,
    "evidenceNode": EvidenceNodeV1.from_json_obj,
    "projectedNode": ProjectedNodeV1.from_json_obj,
    "citationAddress": CitationAddressV1.from_json_obj,
}


def _selector_is_contained_by_node(
    citation: CitationAddressV1,
    node: EvidenceNodeV1,
) -> bool:
    selector = citation.selector.to_json_obj()
    locator = node.source_locator.to_json_obj()
    selector_kind = selector["kind"]
    locator_kind = locator["kind"]

    if selector_kind == "node":
        return selector["anchorId"] == node.anchor_id
    if selector_kind == "lineRange":
        return (
            locator_kind == "textFile"
            and locator["startLine"] <= selector["startLine"]
            and selector["endLine"] <= locator["endLine"]
        )
    if selector_kind == "textSpan":
        return (
            locator_kind == "textFile"
            and locator["startOffset"] <= selector["startOffset"]
            and selector["endOffset"] <= locator["endOffset"]
        )
    if selector_kind == "section":
        if locator_kind != "section":
            return False
        locator_path = locator["sectionOrdinalPath"]
        selector_path = selector["sectionOrdinalPath"]
        return selector_path[: len(locator_path)] == locator_path
    if selector_kind == "tableRange":
        return (
            locator_kind == "tableRange"
            and selector["tableOrdinalPath"] == locator["tableOrdinalPath"]
            and locator["startRow"] <= selector["startRow"]
            and selector["endRow"] <= locator["endRow"]
            and locator["startColumn"] <= selector["startColumn"]
            and selector["endColumn"] <= locator["endColumn"]
        )
    if selector_kind not in {"pageRegion", "mediaRegion"} or selector_kind != locator_kind:
        return False
    if selector["coordinateProfile"] != locator["coordinateProfile"]:
        return False
    if selector_kind == "pageRegion" and selector["pageNumber"] != locator["pageNumber"]:
        return False
    if selector_kind == "mediaRegion" and selector["mediaObjectId"] != locator["mediaObjectId"]:
        return False
    return (
        locator["x"] <= selector["x"]
        and locator["y"] <= selector["y"]
        and selector["x"] + selector["width"] <= locator["x"] + locator["width"]
        and selector["y"] + selector["height"] <= locator["y"] + locator["height"]
    )


def _hierarchy_bundle_is_coherent(bundle: dict[str, object]) -> bool:
    try:
        source_values = bundle["sourceObjectVersions"]
        node_values = bundle["evidenceNodes"]
        projected_values = bundle["projectedNodes"]
        citation_values = bundle["citationAddresses"]
        if not all(
            type(values) is list
            for values in (source_values, node_values, projected_values, citation_values)
        ):
            return False
        sources = tuple(SourceObjectVersionV1.from_json_obj(value) for value in source_values)
        evidence = EvidenceVersionV1.from_json_obj(bundle["evidenceVersion"])
        structure = StructureRevisionV1.from_json_obj(bundle["structureRevision"])
        projection = ProjectionRevisionV1.from_json_obj(bundle["projectionRevision"])
        snapshot = FilesystemSnapshotV1.from_json_obj(bundle["filesystemSnapshot"])
        nodes = tuple(EvidenceNodeV1.from_json_obj(value) for value in node_values)
        projected_nodes = tuple(ProjectedNodeV1.from_json_obj(value) for value in projected_values)
        citations = tuple(CitationAddressV1.from_json_obj(value) for value in citation_values)
    except (KeyError, TypeError, ValueError):
        return False

    source_ids = [source.source_version_id for source in sources]
    source_by_id = {source.source_version_id: source for source in sources}
    evidence_source_ids = set(evidence.source_version_ids)
    if len(source_ids) != len(set(source_ids)) or set(source_ids) != evidence_source_ids:
        return False
    entry_by_id = {entry.entry_id: entry for entry in snapshot.inventory_entries}
    admitted_file_by_source_and_path: dict[tuple[str, str], FilesystemInventoryEntryV1] = {}
    for entry in snapshot.inventory_entries:
        if entry.source_version_id is None:
            continue
        source = source_by_id.get(entry.source_version_id)
        if (
            source is None
            or entry.source_version_id not in evidence_source_ids
            or entry.entry_kind is not FilesystemEntryKindV1.FILE
            or entry.status is not FilesystemEntryStatusV1.ADMITTED
            or entry.byte_size != source.byte_size
            or entry.content_sha256 != source.content_sha256
            or entry.media_type != source.media_type
        ):
            return False
        admitted_file_by_source_and_path[(entry.source_version_id, entry.relative_path)] = entry
    if snapshot.root_source_version_id is not None:
        root_entry = entry_by_id.get(snapshot.admitted_root_id)
        if (
            snapshot.root_source_version_id not in evidence_source_ids
            or snapshot.root_source_version_id not in source_by_id
            or root_entry is None
            or root_entry.status is not FilesystemEntryStatusV1.ADMITTED
            or root_entry.source_version_id != snapshot.root_source_version_id
        ):
            return False

    node_pairs = {(node.anchor_id, node.occurrence_id) for node in nodes}
    if len(node_pairs) != len(nodes):
        return False
    node_by_pair = {(node.anchor_id, node.occurrence_id): node for node in nodes}
    root_pairs = [
        pair
        for pair, node in node_by_pair.items()
        if node.parent_anchor_id is None and node.parent_occurrence_id is None
    ]
    if len(root_pairs) != 1:
        return False
    root_pair = root_pairs[0]
    root = node_by_pair[root_pair]
    if root.node_kind is not EvidenceNodeKindV1.ROOT or root.ordinal != 0:
        return False
    if structure.evidence_version_id != evidence.evidence_version_id:
        return False
    sibling_ordinals: set[tuple[str | None, str | None, ContainmentKindV1, int]] = set()
    non_physical_children: dict[tuple[str, str], list[tuple[str, str]]] = {}
    for node in nodes:
        if (
            node.evidence_version_id != evidence.evidence_version_id
            or node.structure_revision_id != structure.structure_revision_id
            or node.root_anchor_id != root.anchor_id
        ):
            return False
        parent_pair = (node.parent_anchor_id, node.parent_occurrence_id)
        if node.parent_anchor_id is not None and parent_pair not in node_pairs:
            return False
        ordinal_key = (
            node.parent_anchor_id,
            node.parent_occurrence_id,
            node.containment_kind,
            node.ordinal,
        )
        if ordinal_key in sibling_ordinals:
            return False
        sibling_ordinals.add(ordinal_key)
        if (
            node.parent_anchor_id is not None
            and node.parent_occurrence_id is not None
            and node.containment_kind is not ContainmentKindV1.PHYSICAL
        ):
            non_physical_children.setdefault(
                (node.parent_anchor_id, node.parent_occurrence_id), []
            ).append((node.anchor_id, node.occurrence_id))
        locator = source_locator_from_json_obj(node.source_locator.to_json_obj()).to_json_obj()
        if locator["kind"] == "filesystemInventoryEntry":
            if (
                locator["snapshotId"] != snapshot.snapshot_id
                or locator["entryId"] not in entry_by_id
            ):
                return False
        elif locator["sourceVersionId"] not in evidence_source_ids:
            return False
        elif locator["kind"] == "textFile":
            entry = admitted_file_by_source_and_path.get(
                (locator["sourceVersionId"], locator["relativePath"])
            )
            if (
                entry is None
                or entry.encoding_profile
                not in {
                    TextEncodingProfileV1.UTF8,
                    TextEncodingProfileV1.UTF8_BOM,
                    TextEncodingProfileV1.ASCII,
                }
                or entry.media_type is None
                or not entry.media_type.startswith("text/")
                or entry.byte_size is None
                or locator["endOffset"] > entry.byte_size
            ):
                return False

    for pair in node_pairs:
        current = pair
        ancestors: set[tuple[str, str]] = set()
        while current != root_pair:
            if current in ancestors:
                return False
            ancestors.add(current)
            current_node = node_by_pair[current]
            if current_node.parent_anchor_id is None or current_node.parent_occurrence_id is None:
                return False
            current = (
                current_node.parent_anchor_id,
                current_node.parent_occurrence_id,
            )
            if current not in node_by_pair:
                return False

    if projection.structure_revision_id != structure.structure_revision_id:
        return False
    projected_by_key: dict[tuple[str, str, str], ProjectedNodeV1] = {}
    for projected in projected_nodes:
        pair = (projected.anchor_id, projected.occurrence_id)
        projected_key = (
            projected.structure_revision_id,
            projected.anchor_id,
            projected.occurrence_id,
        )
        if (
            projected.projection_revision_id != projection.projection_revision_id
            or projected.structure_revision_id != structure.structure_revision_id
            or pair not in node_pairs
            or projected_key in projected_by_key
        ):
            return False
        projected_by_key[projected_key] = projected

    for citation in citations:
        if citation.occurrence_id is None:
            return False
        pair = (citation.anchor_id, citation.occurrence_id)
        if (
            citation.evidence_version_id != evidence.evidence_version_id
            or citation.structure_revision_id != structure.structure_revision_id
            or citation.projection_revision_id != projection.projection_revision_id
            or citation.projection_profile_id != projection.projection_profile_id
            or citation.projection_profile_version != projection.projection_profile_version
            or citation.projection_payload_sha256 != projection.payload_sha256
            or pair not in node_pairs
        ):
            return False
        node = node_by_pair[pair]
        if citation.root_anchor_id != node.root_anchor_id:
            return False
        selected_projected = projected_by_key.get(
            (citation.structure_revision_id, citation.anchor_id, citation.occurrence_id)
        )
        if (
            selected_projected is None
            or selected_projected.citable_state is not CitableStateV1.CITABLE
        ):
            return False
        if _selector_is_contained_by_node(citation, node):
            continue
        pending = list(non_physical_children.get(pair, ()))
        visited: set[tuple[str, str]] = set()
        while pending:
            descendant_pair = pending.pop()
            if descendant_pair in visited:
                continue
            visited.add(descendant_pair)
            descendant = node_by_pair[descendant_pair]
            descendant_projected = projected_by_key.get(
                (
                    descendant.structure_revision_id,
                    descendant.anchor_id,
                    descendant.occurrence_id,
                )
            )
            if (
                descendant_projected is not None
                and descendant_projected.citable_state is CitableStateV1.CITABLE
                and _selector_is_contained_by_node(citation, descendant)
            ):
                break
            pending.extend(non_physical_children.get(descendant_pair, ()))
        else:
            return False

    return True


def test_issue_30_identity_and_text_citation_digests_are_frozen() -> None:
    vectors = json.loads((ROOT / "vectors/v1/identity-citation.json").read_text())

    actual = {
        "sourceObjectVersion": vectors["identityChain"]["sourceObjectVersion"]["canonicalSha256"],
        "evidenceVersion": vectors["identityChain"]["evidenceVersion"]["canonicalSha256"],
        "structureRevision": vectors["identityChain"]["structureRevision"]["canonicalSha256"],
        "projectionRevision": vectors["identityChain"]["projectionRevision"]["canonicalSha256"],
        **{case["name"]: case["canonicalSha256"] for case in vectors["positiveCitationCases"]},
    }

    assert actual == {
        "sourceObjectVersion": "ad3f902c6a97848d5fdc6c1b041b43dec41cc0ae259914210a84aa114c67ba5f",
        "evidenceVersion": "3cc21db8e29b537e318fa3c446f00f061028266920bb8609d74a9c547fa4adb3",
        "structureRevision": "9940a8b4f5d5659405c157423096d89f875c96f916a9e7b97aa0927813f8ad97",
        "projectionRevision": "15d8cfddf65117d8428de61653f783acaa2f9ce68dedaac885c584f7a76dcfdb",
        "line-range-policy-limitation": (
            "cc2d2880834cc6e8befe6c222b1c1ab9c4853c22992e0b2d5b2498d43b17100b"
        ),
        "node-policy-root": "0666bec64bb551d4adad8484c498209bb99d806793acac06423eeae60c72439c",
        "text-span-policy-exception": (
            "1d6d0814db120b2eed52765a800ea665bb1ef9512e7f8961e4967880ce10c463"
        ),
    }


def test_issue_30_schema_defs_are_frozen_except_citation_selector_dispatch() -> None:
    schema = json.loads((ROOT / "schemas/v1/contracts.schema.json").read_text())
    issue_30_names = (
        "noJsonLineTerminators",
        "sha256",
        "identifier",
        "safeNonNegativeInteger",
        "code",
        "mediaType",
        "sourceObjectVersion",
        "evidenceVersion",
        "structureRevision",
        "projectionRevision",
        "nodeSelector",
        "lineRangeSelector",
        "textSpanSelector",
        "citationAddress",
    )
    issue_30_defs = {name: schema["$defs"][name] for name in issue_30_names}
    citation_address = issue_30_defs["citationAddress"]
    issue_30_defs["citationAddress"] = {
        **citation_address,
        "properties": {
            key: value for key, value in citation_address["properties"].items() if key != "selector"
        },
    }
    frozen_payload = {"rootOneOf": schema["oneOf"][:5], "defsExceptCitationSelector": issue_30_defs}
    canonical = json.dumps(
        frozen_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()

    assert (
        hashlib.sha256(canonical).hexdigest()
        == "e4fb1fee57e7ed0698d956add9d88393b3fc7a58dafed9f5d422ed2401911930"
    )


def test_draft_vectors_match_schema_python_round_trip_chain_and_manifest() -> None:
    schema_bytes = (ROOT / "schemas/v1/contracts.schema.json").read_bytes()
    vector_bytes = (ROOT / "vectors/v1/identity-citation.json").read_bytes()
    hierarchy_bytes = (ROOT / "vectors/v1/hierarchy-selectors.json").read_bytes()
    manifest = json.loads((ROOT / "vectors/v1/manifest.json").read_text(encoding="utf-8"))
    schema = json.loads(schema_bytes)
    vectors = json.loads(vector_bytes)

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)

    decoded: dict[str, object] = {}
    for kind, case in vectors["identityChain"].items():
        validator.validate(case["value"])
        contract = IDENTITY_READERS[kind](case["value"])
        assert contract.to_json_obj() == case["value"]
        assert contract.digest == case["canonicalSha256"]
        decoded[kind] = contract

    source = decoded["sourceObjectVersion"]
    evidence = decoded["evidenceVersion"]
    structure = decoded["structureRevision"]
    projection = decoded["projectionRevision"]
    assert evidence.source_version_ids == (source.source_version_id,)
    assert structure.evidence_version_id == evidence.evidence_version_id
    assert projection.structure_revision_id == structure.structure_revision_id

    for case in vectors["positiveCitationCases"]:
        validator.validate(case["value"])
        address = CitationAddressV1.from_json_obj(case["value"])
        assert address.to_json_obj() == case["value"]
        assert address.digest == case["canonicalSha256"]
        assert address.evidence_version_id == evidence.evidence_version_id
        assert address.structure_revision_id == structure.structure_revision_id
        assert address.projection_revision_id == projection.projection_revision_id
        assert address.projection_profile_id == projection.projection_profile_id
        assert address.projection_profile_version == projection.projection_profile_version
        assert address.projection_payload_sha256 == projection.payload_sha256

    assert manifest == {
        "schemaVersion": 1,
        "files": [
            {
                "path": "schemas/v1/contracts.schema.json",
                "sha256": hashlib.sha256(schema_bytes).hexdigest(),
            },
            {
                "path": "vectors/v1/identity-citation.json",
                "sha256": hashlib.sha256(vector_bytes).hexdigest(),
            },
            {
                "path": "vectors/v1/hierarchy-selectors.json",
                "sha256": hashlib.sha256(hierarchy_bytes).hexdigest(),
            },
        ],
    }


def test_schema_negative_identity_vectors_are_rejected_by_schema_and_python() -> None:
    schema = json.loads((ROOT / "schemas/v1/contracts.schema.json").read_text())
    vectors = json.loads((ROOT / "vectors/v1/identity-citation.json").read_text())
    validator = Draft202012Validator(schema)

    for case in vectors["schemaNegativeIdentityCases"]:
        assert list(validator.iter_errors(case["value"])), case["name"]
        try:
            IDENTITY_READERS[case["kind"]](case["value"])
        except ValueError:
            pass
        else:
            raise AssertionError(f"Python accepted negative vector {case['name']}")


def test_schema_negative_citation_vectors_are_rejected_by_schema_and_python() -> None:
    schema = json.loads((ROOT / "schemas/v1/contracts.schema.json").read_text())
    vectors = json.loads((ROOT / "vectors/v1/identity-citation.json").read_text())
    validator = Draft202012Validator(schema)

    for case in vectors["schemaNegativeCitationCases"]:
        assert list(validator.iter_errors(case["value"])), case["name"]
        try:
            CitationAddressV1.from_json_obj(case["value"])
        except ValueError:
            pass
        else:
            raise AssertionError(f"Python accepted negative vector {case['name']}")


def test_schema_rejects_newline_suffixed_shared_scalar_references() -> None:
    schema = json.loads((ROOT / "schemas/v1/contracts.schema.json").read_text())
    vectors = json.loads((ROOT / "vectors/v1/identity-citation.json").read_text())
    validator = Draft202012Validator(schema)

    cases = vectors["schemaNegativeIdentityCases"] + vectors["schemaNegativeCitationCases"]
    newline_cases = [case for case in cases if case["name"].startswith("newline-suffixed-")]

    assert {case["name"] for case in newline_cases} == {
        "newline-suffixed-source-digest",
        "newline-suffixed-source-identifier",
        "newline-suffixed-evidence-code",
        "newline-suffixed-source-media-type",
        "newline-suffixed-citation-digest",
        "newline-suffixed-citation-identifier",
    }
    for case in newline_cases:
        assert list(validator.iter_errors(case["value"])), case["name"]


def test_semantic_negative_vectors_document_schema_number_limitation_and_python_gate() -> None:
    schema = json.loads((ROOT / "schemas/v1/contracts.schema.json").read_text())
    vectors = json.loads((ROOT / "vectors/v1/identity-citation.json").read_text())
    validator = Draft202012Validator(schema)

    number_cases = [
        case
        for case in vectors["semanticNegativeContractCases"]
        if case["expectedError"] == "CANONICAL_NUMBER_TYPE"
    ]

    assert {case["name"] for case in number_cases} == {
        "float-source-byte-size",
        "float-line-range-coordinate",
        "float-text-span-coordinate",
    }
    for case in number_cases:
        assert list(validator.iter_errors(case["value"])) == [], case["name"]
        try:
            if case["kind"] == "citationAddress":
                CitationAddressV1.from_json_obj(case["value"])
            else:
                IDENTITY_READERS[case["kind"]](case["value"])
        except ValueError:
            pass
        else:
            raise AssertionError(f"Python accepted semantic number vector {case['name']}")


def test_semantic_negative_vectors_are_rejected_by_python() -> None:
    vectors = json.loads((ROOT / "vectors/v1/identity-citation.json").read_text())
    cases = vectors["semanticNegativeCitationCases"] + vectors["semanticNegativeContractCases"]
    for case in cases:
        kind = case.get("kind", "citationAddress")
        try:
            if kind == "citationAddress":
                CitationAddressV1.from_json_obj(case["value"])
            else:
                IDENTITY_READERS[kind](case["value"])
        except ValueError:
            pass
        else:
            raise AssertionError(f"Python accepted semantic negative vector {case['name']}")


def test_cross_reference_negative_vectors_are_rejected_by_conformance_check() -> None:
    vectors = json.loads((ROOT / "vectors/v1/identity-citation.json").read_text())
    for case in vectors["crossReferenceNegativeCases"]:
        source = SourceObjectVersionV1.from_json_obj(case["sourceObjectVersion"])
        evidence = EvidenceVersionV1.from_json_obj(case["evidenceVersion"])
        structure = StructureRevisionV1.from_json_obj(case["structureRevision"])
        projection = ProjectionRevisionV1.from_json_obj(case["projectionRevision"])
        citation = CitationAddressV1.from_json_obj(case["citationAddress"])
        coherent = (
            evidence.source_version_ids == (source.source_version_id,)
            and structure.evidence_version_id == evidence.evidence_version_id
            and projection.structure_revision_id == structure.structure_revision_id
            and citation.evidence_version_id == evidence.evidence_version_id
            and citation.structure_revision_id == structure.structure_revision_id
            and citation.projection_revision_id == projection.projection_revision_id
            and citation.projection_profile_id == projection.projection_profile_id
            and citation.projection_profile_version == projection.projection_profile_version
            and citation.projection_payload_sha256 == projection.payload_sha256
        )
        assert case["expectedError"] == "REFERENCE_MISMATCH"
        assert not coherent, case["name"]


def test_hierarchy_vectors_match_schema_python_round_trip_chain_and_manifest() -> None:
    schema_bytes = (ROOT / "schemas/v1/contracts.schema.json").read_bytes()
    identity_bytes = (ROOT / "vectors/v1/identity-citation.json").read_bytes()
    hierarchy_bytes = (ROOT / "vectors/v1/hierarchy-selectors.json").read_bytes()
    manifest = json.loads((ROOT / "vectors/v1/manifest.json").read_text(encoding="utf-8"))
    schema = json.loads(schema_bytes)
    vectors = json.loads(hierarchy_bytes)

    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    locator_validator = Draft202012Validator(
        {"$defs": schema["$defs"], "$ref": "#/$defs/sourceLocator"}
    )
    selector_validator = Draft202012Validator(
        {"$defs": schema["$defs"], "$ref": "#/$defs/citationSelector"}
    )
    assert schema["$defs"]["citationAddress"]["properties"]["selector"] == {
        "$ref": "#/$defs/citationSelector"
    }

    for group in ("positiveFilesystemCases", "positiveHierarchyCases", "positiveProjectionCases"):
        for case in vectors[group]:
            validator.validate(case["value"])
            contract = HIERARCHY_READERS[case["kind"]](case["value"])
            assert contract.to_json_obj() == case["value"]
            assert contract.digest == case["canonicalSha256"]

    for case in vectors["positiveLocatorCases"]:
        locator_validator.validate(case["value"])
        locator = source_locator_from_json_obj(case["value"])
        assert locator.to_json_obj() == case["value"]
        assert canonical_json_sha256(case["value"]) == case["canonicalSha256"]

    for case in vectors["positiveSelectorCases"]:
        selector_validator.validate(case["value"])
        assert canonical_json_sha256(case["value"]) == case["canonicalSha256"]

    for case in vectors["positiveCitationCases"]:
        validator.validate(case["value"])
        citation = CitationAddressV1.from_json_obj(case["value"])
        assert citation.to_json_obj() == case["value"]
        assert citation.digest == case["canonicalSha256"]
        assert citation.occurrence_id is not None

    assert manifest == {
        "schemaVersion": 1,
        "files": [
            {
                "path": "schemas/v1/contracts.schema.json",
                "sha256": hashlib.sha256(schema_bytes).hexdigest(),
            },
            {
                "path": "vectors/v1/identity-citation.json",
                "sha256": hashlib.sha256(identity_bytes).hexdigest(),
            },
            {
                "path": "vectors/v1/hierarchy-selectors.json",
                "sha256": hashlib.sha256(hierarchy_bytes).hexdigest(),
            },
        ],
    }


def test_hierarchy_schema_negative_vectors_are_rejected_by_schema_and_python() -> None:
    schema = json.loads((ROOT / "schemas/v1/contracts.schema.json").read_text())
    vectors = json.loads((ROOT / "vectors/v1/hierarchy-selectors.json").read_text())
    validator = Draft202012Validator(schema)

    for case in vectors["schemaNegativeCases"]:
        assert list(validator.iter_errors(case["value"])), case["name"]
        try:
            HIERARCHY_READERS[case["kind"]](case["value"])
        except ValueError:
            pass
        else:
            raise AssertionError(f"Python accepted schema-negative vector {case['name']}")


def test_hierarchy_semantic_negative_vectors_are_rejected_by_python() -> None:
    vectors = json.loads((ROOT / "vectors/v1/hierarchy-selectors.json").read_text())
    for case in vectors["semanticNegativeCases"]:
        try:
            HIERARCHY_READERS[case["kind"]](case["value"])
        except ValueError:
            pass
        else:
            raise AssertionError(f"Python accepted semantic-negative vector {case['name']}")


def test_complete_hierarchy_bundle_is_coherent() -> None:
    vectors = json.loads((ROOT / "vectors/v1/hierarchy-selectors.json").read_text())

    assert _hierarchy_bundle_is_coherent(vectors["positiveHierarchyBundle"]) is True


def test_hierarchy_vectors_reject_noncanonical_semantic_hierarchies() -> None:
    vectors = json.loads((ROOT / "vectors/v1/hierarchy-selectors.json").read_text())
    expected_names = {
        "multiple-semantic-roots",
        "semantic-root-kind-mismatch",
        "semantic-root-ordinal-mismatch",
        "semantic-parent-cycle",
        "duplicate-semantic-sibling-ordinal",
    }
    cases = [
        case for case in vectors["crossReferenceNegativeCases"] if case["name"] in expected_names
    ]

    assert {case["name"] for case in cases} == expected_names
    for case in cases:
        reader = {**IDENTITY_READERS, **HIERARCHY_READERS}[case["kind"]]
        reader(case["value"])
        assert case["expectedError"] == "REFERENCE_MISMATCH"
        assert _hierarchy_bundle_is_coherent(case["bundle"]) is False, case["name"]


def test_hierarchy_vectors_reject_incoherent_sources_snapshots_and_text_locators() -> None:
    vectors = json.loads((ROOT / "vectors/v1/hierarchy-selectors.json").read_text())
    expected_names = {
        "root-source-version-does-not-identify-root-entry",
        "admitted-entry-byte-size-mismatch",
        "admitted-entry-content-digest-mismatch",
        "admitted-entry-media-type-mismatch",
        "text-locator-image-source",
        "text-locator-blocked-entry",
        "text-locator-path-mismatch",
        "text-locator-unsupported-encoding",
        "text-locator-out-of-bounds",
    }
    cases = [
        case for case in vectors["crossReferenceNegativeCases"] if case["name"] in expected_names
    ]

    assert {case["name"] for case in cases} == expected_names
    for case in cases:
        reader = {**IDENTITY_READERS, **HIERARCHY_READERS}[case["kind"]]
        reader(case["value"])
        assert case["expectedError"] == "REFERENCE_MISMATCH"
        assert _hierarchy_bundle_is_coherent(case["bundle"]) is False, case["name"]


def test_hierarchy_vectors_enforce_projected_citability_and_descendant_selectors() -> None:
    vectors = json.loads((ROOT / "vectors/v1/hierarchy-selectors.json").read_text())
    expected_negative_names = {
        "selected-node-absent-from-projection",
        "selected-node-not-citable",
        "descendant-node-not-citable",
        "duplicate-projected-node-identity",
        "physical-descendant-selector-path",
    }
    positive = next(
        case
        for case in vectors["positiveCitationCases"]
        if case["name"] == "parent-section-descendant-table-citation"
    )
    cases = [
        case
        for case in vectors["crossReferenceNegativeCases"]
        if case["name"] in expected_negative_names
    ]

    assert CitationAddressV1.from_json_obj(positive["value"]).digest == positive["canonicalSha256"]
    assert _hierarchy_bundle_is_coherent(vectors["positiveHierarchyBundle"]) is True
    assert {case["name"] for case in cases} == expected_negative_names
    for case in cases:
        reader = {**IDENTITY_READERS, **HIERARCHY_READERS}[case["kind"]]
        reader(case["value"])
        assert case["expectedError"] == "REFERENCE_MISMATCH"
        assert _hierarchy_bundle_is_coherent(case["bundle"]) is False, case["name"]


def test_hierarchy_cross_reference_negative_vectors_are_rejected_by_conformance_check() -> None:
    vectors = json.loads((ROOT / "vectors/v1/hierarchy-selectors.json").read_text())
    for case in vectors["crossReferenceNegativeCases"]:
        reader = {**IDENTITY_READERS, **HIERARCHY_READERS}[case["kind"]]
        reader(case["value"])
        assert case["expectedError"] == "REFERENCE_MISMATCH"
        assert _hierarchy_bundle_is_coherent(case["bundle"]) is False, case["name"]
