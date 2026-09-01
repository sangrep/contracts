"""Read-only filesystem snapshot contracts for wire schema v1."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Self

from .canonical import (
    ContractValidationError,
    JsonValue,
    canonical_json_sha256,
    canonical_json_sha256_omitting_field_v1,
    require_sha256,
)
from .identity import (
    _require_code_tuple,
    _require_enum,
    _require_exact_wire_fields,
    _require_identifier,
    _require_json_object,
    _require_kind,
    _require_media_type,
    _require_non_negative_int,
    _require_schema_version,
    _require_string,
    _validate_canonical_wire,
)


class FilesystemEntryKindV1(str, Enum):
    DIRECTORY = "directory"
    FILE = "file"
    SYMLINK = "symlink"
    SPECIAL = "special"


class FilesystemEntryStatusV1(str, Enum):
    ADMITTED = "admitted"
    INVENTORIED = "inventoried"
    BLOCKED = "blocked"
    OMITTED = "omitted"


class TextEncodingProfileV1(str, Enum):
    UTF8 = "utf8"
    UTF8_BOM = "utf8Bom"
    ASCII = "ascii"
    UNSUPPORTED = "unsupported"
    UNKNOWN = "unknown"


class NewlineProfileV1(str, Enum):
    LF = "lf"
    CRLF = "crlf"
    CR = "cr"
    MIXED = "mixed"
    NONE = "none"
    UNKNOWN = "unknown"


SAFE_RELATIVE_PATH_FORBIDDEN = re.compile(
    r"(^/|/$|\\|\x00|[\r\n\u2028\u2029]|(^|/)(\.|\.\.)(/|$)|//|^[A-Za-z][A-Za-z0-9+.-]*:|^[A-Za-z]:)"
)


def require_safe_relative_path_label_v1(
    value: str,
    *,
    is_root: bool,
    field_name: str = "relative_path",
) -> str:
    if type(value) is not str:
        raise ContractValidationError(f"{field_name} must be a safe relative path label.")
    if value == "":
        raise ContractValidationError(f"{field_name} must be a safe relative path label.")
    if value == ".":
        if is_root:
            return value
        raise ContractValidationError(f"{field_name} may be '.' only for the root entry.")
    if is_root:
        raise ContractValidationError(f"{field_name} for the root entry must be '.'.")
    if len(value.encode("utf-8")) > 1024 or SAFE_RELATIVE_PATH_FORBIDDEN.search(value):
        raise ContractValidationError(f"{field_name} must be a safe relative path label.")
    _validate_canonical_wire({"relativePath": value})
    return value


def _optional_identifier(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_identifier(_require_string(value, field_name=field_name), field_name=field_name)


def _optional_non_negative_int(value: object, *, field_name: str) -> int | None:
    if value is None:
        return None
    return _require_non_negative_int(value, field_name=field_name)


def _optional_sha256(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return require_sha256(_require_string(value, field_name=field_name), field_name=field_name)


def _optional_media_type(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_media_type(value, field_name=field_name)


def _parse_code_list(value: object, *, field_name: str) -> tuple[str, ...]:
    if type(value) is not list:
        raise ContractValidationError(f"{field_name} must be a JSON array.")
    return _require_code_tuple(tuple(value), field_name=field_name)


@dataclass(frozen=True, slots=True)
class FilesystemInventoryEntryV1:
    entry_id: str
    parent_entry_id: str | None
    entry_kind: FilesystemEntryKindV1
    status: FilesystemEntryStatusV1
    relative_path: str
    ordinal: int
    byte_size: int | None
    content_sha256: str | None
    media_type: str | None
    encoding_profile: TextEncodingProfileV1
    newline_profile: NewlineProfileV1
    source_version_id: str | None
    warning_codes: tuple[str, ...] = ()
    omission_codes: tuple[str, ...] = ()

    _WIRE_KIND: ClassVar[str] = "filesystemInventoryEntry"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schemaVersion",
            "kind",
            "entryId",
            "parentEntryId",
            "entryKind",
            "status",
            "relativePath",
            "ordinal",
            "byteSize",
            "contentSha256",
            "mediaType",
            "encodingProfile",
            "newlineProfile",
            "sourceVersionId",
            "warningCodes",
            "omissionCodes",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.entry_id, field_name="entry_id")
        _optional_identifier(self.parent_entry_id, field_name="parent_entry_id")
        if not isinstance(self.entry_kind, FilesystemEntryKindV1):
            raise ContractValidationError("entry_kind contains an unknown enum value.")
        if not isinstance(self.status, FilesystemEntryStatusV1):
            raise ContractValidationError("status contains an unknown enum value.")
        require_safe_relative_path_label_v1(
            self.relative_path,
            is_root=self.parent_entry_id is None,
        )
        _require_non_negative_int(self.ordinal, field_name="ordinal")
        _optional_non_negative_int(self.byte_size, field_name="byte_size")
        _optional_sha256(self.content_sha256, field_name="content_sha256")
        _optional_media_type(self.media_type, field_name="media_type")
        if not isinstance(self.encoding_profile, TextEncodingProfileV1):
            raise ContractValidationError("encoding_profile contains an unknown enum value.")
        if not isinstance(self.newline_profile, NewlineProfileV1):
            raise ContractValidationError("newline_profile contains an unknown enum value.")
        _optional_identifier(self.source_version_id, field_name="source_version_id")
        _require_code_tuple(self.warning_codes, field_name="warning_codes")
        _require_code_tuple(self.omission_codes, field_name="omission_codes")
        _validate_file_entry_metadata(self)
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": self._WIRE_KIND,
            "entryId": self.entry_id,
            "parentEntryId": self.parent_entry_id,
            "entryKind": self.entry_kind.value,
            "status": self.status.value,
            "relativePath": self.relative_path,
            "ordinal": self.ordinal,
            "byteSize": self.byte_size,
            "contentSha256": self.content_sha256,
            "mediaType": self.media_type,
            "encodingProfile": self.encoding_profile.value,
            "newlineProfile": self.newline_profile.value,
            "sourceVersionId": self.source_version_id,
            "warningCodes": list(self.warning_codes),
            "omissionCodes": list(self.omission_codes),
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_schema_version(payload["schemaVersion"])
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                entry_id=_require_identifier(
                    _require_string(payload["entryId"], field_name="entryId"),
                    field_name="entryId",
                ),
                parent_entry_id=_optional_identifier(
                    payload["parentEntryId"], field_name="parentEntryId"
                ),
                entry_kind=_require_enum(
                    FilesystemEntryKindV1, payload["entryKind"], field_name="entryKind"
                ),
                status=_require_enum(
                    FilesystemEntryStatusV1, payload["status"], field_name="status"
                ),
                relative_path=_require_string(payload["relativePath"], field_name="relativePath"),
                ordinal=_require_non_negative_int(payload["ordinal"], field_name="ordinal"),
                byte_size=_optional_non_negative_int(payload["byteSize"], field_name="byteSize"),
                content_sha256=_optional_sha256(
                    payload["contentSha256"], field_name="contentSha256"
                ),
                media_type=_optional_media_type(payload["mediaType"], field_name="mediaType"),
                encoding_profile=_require_enum(
                    TextEncodingProfileV1,
                    payload["encodingProfile"],
                    field_name="encodingProfile",
                ),
                newline_profile=_require_enum(
                    NewlineProfileV1,
                    payload["newlineProfile"],
                    field_name="newlineProfile",
                ),
                source_version_id=_optional_identifier(
                    payload["sourceVersionId"], field_name="sourceVersionId"
                ),
                warning_codes=_parse_code_list(payload["warningCodes"], field_name="warningCodes"),
                omission_codes=_parse_code_list(
                    payload["omissionCodes"], field_name="omissionCodes"
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_json_obj())


def _validate_file_entry_metadata(entry: FilesystemInventoryEntryV1) -> None:
    if entry.status is FilesystemEntryStatusV1.OMITTED and not entry.omission_codes:
        raise ContractValidationError("omitted entries require at least one omission code.")
    if entry.status is FilesystemEntryStatusV1.BLOCKED and not (
        entry.warning_codes or entry.omission_codes
    ):
        raise ContractValidationError(
            "blocked entries require at least one warning or omission code."
        )
    if (
        entry.entry_kind is FilesystemEntryKindV1.FILE
        and entry.status is FilesystemEntryStatusV1.ADMITTED
    ):
        if (
            entry.byte_size is None
            or entry.content_sha256 is None
            or entry.media_type is None
            or entry.source_version_id is None
        ):
            raise ContractValidationError(
                "admitted file entries require byte, digest, media, and source metadata."
            )
        return
    if entry.entry_kind is FilesystemEntryKindV1.FILE:
        if entry.content_sha256 is not None or entry.source_version_id is not None:
            raise ContractValidationError(
                "non-admitted file entries must not carry content digest or source version."
            )
        return
    if (
        entry.byte_size is not None
        or entry.content_sha256 is not None
        or entry.media_type is not None
        or entry.source_version_id is not None
    ):
        raise ContractValidationError("non-file entries must not carry file metadata.")


def _validate_snapshot_entries(entries: tuple[FilesystemInventoryEntryV1, ...]) -> None:
    if not entries:
        raise ContractValidationError("inventory_entries must not be empty.")
    root = entries[0]
    if (
        root.parent_entry_id is not None
        or root.relative_path != "."
        or root.entry_kind is not FilesystemEntryKindV1.DIRECTORY
        or root.status is not FilesystemEntryStatusV1.ADMITTED
        or root.ordinal != 0
    ):
        raise ContractValidationError("first inventory entry must be the admitted directory root.")
    seen_entries: set[str] = set()
    seen_sources: set[str] = set()
    ordinals_by_parent: dict[str | None, set[int]] = {}
    next_ordinal_by_parent: dict[str | None, int] = {}
    active_ancestor_ids: list[str] = []
    for entry in entries:
        if entry.entry_id in seen_entries:
            raise ContractValidationError("inventory_entries contains a duplicate entry_id.")
        if entry.parent_entry_id is not None and entry.parent_entry_id not in seen_entries:
            raise ContractValidationError("inventory entry parent must reference an earlier entry.")
        if active_ancestor_ids:
            while active_ancestor_ids[-1] != entry.parent_entry_id:
                active_ancestor_ids.pop()
                if not active_ancestor_ids:
                    raise ContractValidationError(
                        "inventory entries must be in depth-first preorder."
                    )
        parent_ordinals = ordinals_by_parent.setdefault(entry.parent_entry_id, set())
        if entry.ordinal in parent_ordinals:
            raise ContractValidationError("sibling ordinals must be unique.")
        parent_ordinals.add(entry.ordinal)
        expected = next_ordinal_by_parent.setdefault(entry.parent_entry_id, 0)
        if entry.ordinal != expected:
            raise ContractValidationError("sibling ordinals must start at 0 without gaps.")
        next_ordinal_by_parent[entry.parent_entry_id] = expected + 1
        seen_entries.add(entry.entry_id)
        active_ancestor_ids.append(entry.entry_id)
        if entry.source_version_id is not None:
            if entry.source_version_id in seen_sources:
                raise ContractValidationError(
                    "source_version_id values must be unique within a snapshot."
                )
            seen_sources.add(entry.source_version_id)


@dataclass(frozen=True, slots=True)
class FilesystemSnapshotV1:
    snapshot_id: str
    admitted_root_id: str
    adapter_profile_id: str
    adapter_profile_sha256: str
    inventory_entries: tuple[FilesystemInventoryEntryV1, ...]
    root_source_version_id: str | None
    snapshot_sha256: str
    limit_codes: tuple[str, ...] = ()

    _WIRE_KIND: ClassVar[str] = "filesystemSnapshot"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schemaVersion",
            "kind",
            "snapshotId",
            "admittedRootId",
            "adapterProfileId",
            "adapterProfileSha256",
            "inventoryEntries",
            "rootSourceVersionId",
            "limitCodes",
            "snapshotSha256",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.snapshot_id, field_name="snapshot_id")
        _require_identifier(self.admitted_root_id, field_name="admitted_root_id")
        _require_identifier(self.adapter_profile_id, field_name="adapter_profile_id")
        require_sha256(self.adapter_profile_sha256, field_name="adapter_profile_sha256")
        if type(self.inventory_entries) is not tuple or any(
            type(entry) is not FilesystemInventoryEntryV1 for entry in self.inventory_entries
        ):
            raise ContractValidationError(
                "inventory_entries must be a tuple of filesystem inventory entries."
            )
        _optional_identifier(self.root_source_version_id, field_name="root_source_version_id")
        require_sha256(self.snapshot_sha256, field_name="snapshot_sha256")
        _require_code_tuple(self.limit_codes, field_name="limit_codes")
        _validate_snapshot_entries(self.inventory_entries)
        if self.admitted_root_id != self.inventory_entries[0].entry_id:
            raise ContractValidationError(
                "admitted_root_id must identify the first inventory entry."
            )
        _validate_canonical_wire(self.to_json_obj())
        expected_snapshot_sha256 = canonical_json_sha256_omitting_field_v1(
            self.to_json_obj(), field_name="snapshotSha256"
        )
        if self.snapshot_sha256 != expected_snapshot_sha256:
            raise ContractValidationError(
                "snapshot_sha256 must match the snapshotSha256-omitted digest."
            )

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": self._WIRE_KIND,
            "snapshotId": self.snapshot_id,
            "admittedRootId": self.admitted_root_id,
            "adapterProfileId": self.adapter_profile_id,
            "adapterProfileSha256": self.adapter_profile_sha256,
            "inventoryEntries": [entry.to_json_obj() for entry in self.inventory_entries],
            "rootSourceVersionId": self.root_source_version_id,
            "limitCodes": list(self.limit_codes),
            "snapshotSha256": self.snapshot_sha256,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_schema_version(payload["schemaVersion"])
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            inventory_entries_value = payload["inventoryEntries"]
            if type(inventory_entries_value) is not list:
                raise ContractValidationError("inventoryEntries must be a JSON array.")
            return cls(
                snapshot_id=_require_identifier(
                    _require_string(payload["snapshotId"], field_name="snapshotId"),
                    field_name="snapshotId",
                ),
                admitted_root_id=_require_identifier(
                    _require_string(payload["admittedRootId"], field_name="admittedRootId"),
                    field_name="admittedRootId",
                ),
                adapter_profile_id=_require_identifier(
                    _require_string(payload["adapterProfileId"], field_name="adapterProfileId"),
                    field_name="adapterProfileId",
                ),
                adapter_profile_sha256=require_sha256(
                    _require_string(
                        payload["adapterProfileSha256"], field_name="adapterProfileSha256"
                    ),
                    field_name="adapterProfileSha256",
                ),
                inventory_entries=tuple(
                    FilesystemInventoryEntryV1.from_json_obj(entry)
                    for entry in inventory_entries_value
                ),
                root_source_version_id=_optional_identifier(
                    payload["rootSourceVersionId"], field_name="rootSourceVersionId"
                ),
                snapshot_sha256=require_sha256(
                    _require_string(payload["snapshotSha256"], field_name="snapshotSha256"),
                    field_name="snapshotSha256",
                ),
                limit_codes=_parse_code_list(payload["limitCodes"], field_name="limitCodes"),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_json_obj())
