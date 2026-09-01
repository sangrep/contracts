from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace

import pytest

from sangrep_contracts import (
    ContractValidationError,
    FilesystemEntryKindV1,
    FilesystemEntryStatusV1,
    FilesystemInventoryEntryV1,
    FilesystemSnapshotV1,
    NewlineProfileV1,
    TextEncodingProfileV1,
    canonical_json_sha256,
    canonical_json_sha256_omitting_field_v1,
)


def _root() -> FilesystemInventoryEntryV1:
    return FilesystemInventoryEntryV1(
        entry_id="entry:root",
        parent_entry_id=None,
        entry_kind=FilesystemEntryKindV1.DIRECTORY,
        status=FilesystemEntryStatusV1.ADMITTED,
        relative_path=".",
        ordinal=0,
        byte_size=None,
        content_sha256=None,
        media_type=None,
        encoding_profile=TextEncodingProfileV1.UTF8,
        newline_profile=NewlineProfileV1.LF,
        source_version_id=None,
    )


def _file(
    entry_id: str = "entry:policy",
    source_version_id: str = "source:policy:v1",
    content_sha256: str = "1" * 64,
    ordinal: int = 0,
    relative_path: str = "policy.md",
) -> FilesystemInventoryEntryV1:
    return FilesystemInventoryEntryV1(
        entry_id=entry_id,
        parent_entry_id="entry:root",
        entry_kind=FilesystemEntryKindV1.FILE,
        status=FilesystemEntryStatusV1.ADMITTED,
        relative_path=relative_path,
        ordinal=ordinal,
        byte_size=27,
        content_sha256=content_sha256,
        media_type="text/markdown",
        encoding_profile=TextEncodingProfileV1.UTF8,
        newline_profile=NewlineProfileV1.LF,
        source_version_id=source_version_id,
    )


def _blocked() -> FilesystemInventoryEntryV1:
    return FilesystemInventoryEntryV1(
        entry_id="entry:secret",
        parent_entry_id="entry:root",
        entry_kind=FilesystemEntryKindV1.FILE,
        status=FilesystemEntryStatusV1.BLOCKED,
        relative_path="secret.xlsx",
        ordinal=1,
        byte_size=1024,
        content_sha256=None,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        encoding_profile=TextEncodingProfileV1.UNSUPPORTED,
        newline_profile=NewlineProfileV1.UNKNOWN,
        source_version_id=None,
        warning_codes=("unsupported-format",),
    )


def _directory(
    *,
    entry_id: str = "entry:folder",
    parent_entry_id: str = "entry:root",
    relative_path: str = "folder",
    ordinal: int = 0,
    status: FilesystemEntryStatusV1 = FilesystemEntryStatusV1.ADMITTED,
) -> FilesystemInventoryEntryV1:
    return FilesystemInventoryEntryV1(
        entry_id=entry_id,
        parent_entry_id=parent_entry_id,
        entry_kind=FilesystemEntryKindV1.DIRECTORY,
        status=status,
        relative_path=relative_path,
        ordinal=ordinal,
        byte_size=None,
        content_sha256=None,
        media_type=None,
        encoding_profile=TextEncodingProfileV1.UTF8,
        newline_profile=NewlineProfileV1.LF,
        source_version_id=None,
        warning_codes=("blocked-directory",) if status is FilesystemEntryStatusV1.BLOCKED else (),
    )


def _snapshot(*entries: FilesystemInventoryEntryV1) -> FilesystemSnapshotV1:
    snapshot_entries = entries or (_root(), _file(), _blocked())
    snapshot_sha256 = canonical_json_sha256_omitting_field_v1(
        {
            "schemaVersion": 1,
            "kind": "filesystemSnapshot",
            "snapshotId": "snapshot:v1",
            "admittedRootId": "entry:root",
            "adapterProfileId": "filesystem-adapter:v1",
            "adapterProfileSha256": "2" * 64,
            "inventoryEntries": [entry.to_json_obj() for entry in snapshot_entries],
            "rootSourceVersionId": None,
            "limitCodes": [],
            "snapshotSha256": "0" * 64,
        },
        field_name="snapshotSha256",
    )
    return FilesystemSnapshotV1(
        snapshot_id="snapshot:v1",
        admitted_root_id="entry:root",
        adapter_profile_id="filesystem-adapter:v1",
        adapter_profile_sha256="2" * 64,
        inventory_entries=snapshot_entries,
        root_source_version_id=None,
        snapshot_sha256=snapshot_sha256,
        limit_codes=(),
    )


def test_filesystem_inventory_entry_emits_exact_wire_and_round_trips() -> None:
    entry = _file()

    assert entry.to_json_obj() == {
        "schemaVersion": 1,
        "kind": "filesystemInventoryEntry",
        "entryId": "entry:policy",
        "parentEntryId": "entry:root",
        "entryKind": "file",
        "status": "admitted",
        "relativePath": "policy.md",
        "ordinal": 0,
        "byteSize": 27,
        "contentSha256": "1" * 64,
        "mediaType": "text/markdown",
        "encodingProfile": "utf8",
        "newlineProfile": "lf",
        "sourceVersionId": "source:policy:v1",
        "warningCodes": [],
        "omissionCodes": [],
    }
    assert FilesystemInventoryEntryV1.from_json_obj(entry.to_json_obj()) == entry
    assert entry.digest == canonical_json_sha256(entry.to_json_obj())


def test_filesystem_snapshot_validates_root_order_preorder_and_duplicate_content() -> None:
    duplicate_content = _file(
        entry_id="entry:policy-copy",
        source_version_id="source:policy-copy:v1",
        content_sha256="1" * 64,
        ordinal=2,
        relative_path="policy-copy.md",
    )
    snapshot = _snapshot(_root(), _file(), _blocked(), duplicate_content)

    assert FilesystemSnapshotV1.from_json_obj(snapshot.to_json_obj()) == snapshot
    assert (
        snapshot.inventory_entries[1].content_sha256 == snapshot.inventory_entries[3].content_sha256
    )
    assert (
        snapshot.inventory_entries[1].source_version_id
        != snapshot.inventory_entries[3].source_version_id
    )
    assert len(snapshot.digest) == 64


def test_filesystem_snapshot_rejects_entry_subclasses_before_serialization() -> None:
    snapshot = _snapshot()
    assert FilesystemSnapshotV1.from_json_obj(snapshot.to_json_obj()) == snapshot
    entry = snapshot.inventory_entries[1]
    entry_subclass = type(
        "AdversarialFilesystemInventoryEntryV1",
        (FilesystemInventoryEntryV1,),
        {},
    )
    subclass_value = entry_subclass(
        **{field.name: getattr(entry, field.name) for field in fields(entry)}
    )

    def fail_if_serialized(_value: object) -> object:
        raise AssertionError("filesystem entry subclass was serialized")

    entry_subclass.to_json_obj = fail_if_serialized
    entries = (snapshot.inventory_entries[0], subclass_value, *snapshot.inventory_entries[2:])

    with pytest.raises(ContractValidationError, match="inventory_entries"):
        replace(snapshot, inventory_entries=entries)


def test_filesystem_snapshot_requires_admitted_directory_and_path_consistent_parents() -> None:
    file_parent = _file()
    child_of_file = replace(
        _file(
            entry_id="entry:child",
            source_version_id="source:child:v1",
            content_sha256="3" * 64,
            relative_path="policy.md/child.md",
        ),
        parent_entry_id=file_parent.entry_id,
    )
    with pytest.raises(ContractValidationError, match="parent must be an admitted directory"):
        _snapshot(_root(), file_parent, child_of_file)

    directory = _directory()
    unrelated_child = replace(
        _file(relative_path="other/policy.md"),
        parent_entry_id=directory.entry_id,
    )
    with pytest.raises(ContractValidationError, match="direct path descendant"):
        _snapshot(_root(), directory, unrelated_child)

    blocked_directory = _directory(status=FilesystemEntryStatusV1.BLOCKED)
    blocked_child = replace(
        _file(relative_path="folder/policy.md"),
        parent_entry_id=blocked_directory.entry_id,
    )
    with pytest.raises(ContractValidationError, match="parent must be an admitted directory"):
        _snapshot(_root(), blocked_directory, blocked_child)

    valid_child = replace(
        _file(relative_path="folder/policy.md"),
        parent_entry_id=directory.entry_id,
    )
    snapshot = _snapshot(_root(), directory, valid_child)
    assert FilesystemSnapshotV1.from_json_obj(snapshot.to_json_obj()) == snapshot


def test_filesystem_entries_are_frozen_slotted_and_return_fresh_wire_lists() -> None:
    entry = _file()
    snapshot = _snapshot()

    assert not hasattr(entry, "__dict__")
    assert not hasattr(snapshot, "__dict__")
    with pytest.raises(FrozenInstanceError):
        entry.ordinal = 9  # type: ignore[misc]

    first = snapshot.to_json_obj()
    second = snapshot.to_json_obj()
    assert first["inventoryEntries"] is not second["inventoryEntries"]
    first["inventoryEntries"][0]["entryId"] = "entry:mutated"  # type: ignore[index]
    assert FilesystemSnapshotV1.from_json_obj(second) == snapshot


@pytest.mark.parametrize(
    "relative_path",
    [
        "",
        "/policy.md",
        "policy.md/",
        "../policy.md",
        "a/./b.md",
        "a//b.md",
        "C:/case/policy.md",
        "file:policy.md",
        "https://example.test/policy.md",
        "a\\b.md",
        "policy\n.md",
        "policy\u2028.md",
    ],
)
def test_safe_relative_path_rejects_absolute_uri_escape_and_control_labels(
    relative_path: str,
) -> None:
    with pytest.raises(ContractValidationError):
        replace(_file(), relative_path=relative_path)


@pytest.mark.parametrize(
    ("factory", "change"),
    [
        (_file, {"byte_size": None}),
        (_file, {"content_sha256": None}),
        (_file, {"source_version_id": None}),
        (_root, {"byte_size": 1}),
        (_root, {"content_sha256": "1" * 64}),
        (_root, {"media_type": "text/plain"}),
        (_root, {"source_version_id": "source:root"}),
        (_blocked, {"warning_codes": (), "omission_codes": ()}),
        (_blocked, {"status": FilesystemEntryStatusV1.OMITTED, "omission_codes": ()}),
        (_blocked, {"content_sha256": "1" * 64}),
    ],
)
def test_filesystem_entry_rejects_status_kind_metadata_contradictions(
    factory: object,
    change: dict[str, object],
) -> None:
    with pytest.raises(ContractValidationError):
        replace(factory(), **change)  # type: ignore[operator,arg-type]


@pytest.mark.parametrize(
    "entries_factory",
    [
        lambda: (_file(), _root()),
        lambda: (_root(), replace(_file(), parent_entry_id="entry:missing")),
        lambda: (_root(), _file(), replace(_file(), entry_id="entry:copy", ordinal=0)),
        lambda: (
            _root(),
            replace(
                _file(),
                source_version_id="source:policy:v1",
                entry_id="entry:copy",
                ordinal=1,
            ),
        ),
    ],
)
def test_filesystem_snapshot_rejects_order_parent_ordinal_and_source_reuse(
    entries_factory: object,
) -> None:
    with pytest.raises(ContractValidationError):
        _snapshot(*entries_factory())  # type: ignore[operator]


def test_filesystem_snapshot_rejects_child_of_a_closed_preorder_subtree() -> None:
    directory_a = replace(
        _root(),
        entry_id="entry:a",
        parent_entry_id="entry:root",
        relative_path="a",
        ordinal=0,
    )
    directory_b = replace(
        _root(),
        entry_id="entry:b",
        parent_entry_id="entry:root",
        relative_path="b",
        ordinal=1,
    )
    child_a0 = replace(
        _file(),
        entry_id="entry:a-child-0",
        parent_entry_id="entry:a",
        relative_path="a/zero.md",
        source_version_id="source:a-child-0:v1",
    )
    child_a1 = replace(
        _file(),
        entry_id="entry:a-child-1",
        parent_entry_id="entry:a",
        relative_path="a/one.md",
        ordinal=1,
        source_version_id="source:a-child-1:v1",
    )

    with pytest.raises(ContractValidationError):
        _snapshot(_root(), directory_a, child_a0, directory_b, child_a1)


@pytest.mark.parametrize(
    "root",
    [
        replace(
            _root(),
            entry_kind=FilesystemEntryKindV1.FILE,
            byte_size=27,
            content_sha256="1" * 64,
            media_type="text/markdown",
            source_version_id="source:root:v1",
        ),
        replace(_root(), entry_kind=FilesystemEntryKindV1.SYMLINK),
        replace(_root(), entry_kind=FilesystemEntryKindV1.SPECIAL),
    ],
)
def test_filesystem_snapshot_rejects_non_directory_root(root: FilesystemInventoryEntryV1) -> None:
    with pytest.raises(ContractValidationError):
        _snapshot(root)


@pytest.mark.parametrize(
    "root",
    [
        replace(
            _root(),
            status=FilesystemEntryStatusV1.BLOCKED,
            warning_codes=("root-warning",),
        ),
        replace(
            _root(),
            status=FilesystemEntryStatusV1.OMITTED,
            omission_codes=("root-omission",),
        ),
    ],
)
def test_filesystem_snapshot_rejects_non_admitted_root(root: FilesystemInventoryEntryV1) -> None:
    with pytest.raises(ContractValidationError):
        _snapshot(root)


def test_filesystem_snapshot_rejects_nonzero_root_ordinal() -> None:
    with pytest.raises(ContractValidationError):
        _snapshot(replace(_root(), ordinal=1))


def test_filesystem_snapshot_rejects_wrong_lowercase_snapshot_digest() -> None:
    snapshot = _snapshot()

    with pytest.raises(ContractValidationError):
        replace(snapshot, snapshot_sha256="0" * 64)
