"""Pack manifest, compatibility, resource, permission, catalog, and conformance v1."""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from enum import Enum
from typing import Self, TypeVar, cast

from .canonical import (
    MAX_SAFE_INTEGER,
    ContractValidationError,
    JsonObjectValue,
    JsonValue,
    Rfc8785JsonObjectV1,
    freeze_rfc8785_json_object_v1,
    require_sha256,
    rfc8785_json_sha256_omitting_field_v1,
    rfc8785_json_sha256_v1,
    thaw_rfc8785_json_object_v1,
)
from .filesystem import require_safe_relative_path_label_v1
from .schema_bounds import validate_pack_schema_bounds_v1

_PACK_ID = re.compile(r"[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\Z")
_CODE = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:[._-][A-Za-z0-9]+)*\Z")
_MEDIA_TYPE = re.compile(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z")
_SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
_KEY_ID = re.compile(r"ed25519-sha256:[0-9a-f]{64}\Z")
_RELATIVE_PATH = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\Z")
_HOST = re.compile(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?\Z")
MAX_SEMANTIC_VERSION_BYTES = 128
EnumType = TypeVar("EnumType", bound=Enum)


class PackFamilyV1(str, Enum):
    PARSER = "parser"
    INTELLIGENCE = "intelligence"


class PackChannelV1(str, Enum):
    DEVELOPMENT = "development"
    PRERELEASE = "prerelease"
    RELEASE = "release"


class PackExecutionModeV1(str, Enum):
    LOCAL = "local"
    REMOTE = "remote"
    HYBRID = "hybrid"


class PackConformanceVerdictV1(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_QUALIFIED = "notQualified"


@dataclass(frozen=True, slots=True, order=True)
class SemanticVersionV1:
    major: int
    minor: int
    patch: int
    prerelease: tuple[int | str, ...] = ()

    @classmethod
    def parse(cls, value: object, *, field_name: str) -> Self:
        text = _require_string(value, field_name=field_name)
        try:
            encoded_size = len(text.encode("utf-8"))
        except UnicodeEncodeError as error:
            raise ContractValidationError(f"{field_name} must be a semantic version.") from error
        if encoded_size > MAX_SEMANTIC_VERSION_BYTES:
            raise ContractValidationError(f"{field_name} must be a bounded semantic version.")
        match = _SEMVER.fullmatch(text)
        if match is None:
            raise ContractValidationError(f"{field_name} must be a semantic version.")

        def parse_numeric(identifier: str) -> int:
            if len(identifier) > 16:
                raise ContractValidationError(f"{field_name} must be a bounded semantic version.")
            try:
                parsed = int(identifier)
            except ValueError as error:
                raise ContractValidationError(
                    f"{field_name} must be a semantic version."
                ) from error
            if parsed > MAX_SAFE_INTEGER:
                raise ContractValidationError(f"{field_name} must be a bounded semantic version.")
            return parsed

        raw_prerelease = match.group(4)
        prerelease: list[int | str] = []
        if raw_prerelease is not None:
            for identifier in raw_prerelease.split("."):
                if identifier.isdigit():
                    if len(identifier) > 1 and identifier.startswith("0"):
                        raise ContractValidationError(
                            f"{field_name} has a numeric prerelease identifier with a leading zero."
                        )
                    prerelease.append(parse_numeric(identifier))
                else:
                    prerelease.append(identifier)
        return cls(
            parse_numeric(match.group(1)),
            parse_numeric(match.group(2)),
            parse_numeric(match.group(3)),
            tuple(prerelease),
        )

    def _precedence_key(self) -> tuple[object, ...]:
        if not self.prerelease:
            prerelease: tuple[object, ...] = ((2, ""),)
        else:
            prerelease = tuple(
                (0, item) if type(item) is int else (1, item) for item in self.prerelease
            )
        return (self.major, self.minor, self.patch, prerelease)

    def precedes(self, other: SemanticVersionV1) -> bool:
        return self._precedence_key() < other._precedence_key()


@dataclass(frozen=True, slots=True)
class VersionRangeV1:
    minimum_inclusive: SemanticVersionV1
    maximum_exclusive: SemanticVersionV1

    @classmethod
    def from_json_obj(cls, value: object, *, field_name: str) -> Self:
        validate_pack_schema_bounds_v1(value, definition="VersionRangeV1")
        payload = _exact_object(
            value,
            keys={"minimumInclusive", "maximumExclusive"},
            field_name=field_name,
        )
        minimum = SemanticVersionV1.parse(
            payload["minimumInclusive"], field_name=f"{field_name}.minimumInclusive"
        )
        maximum = SemanticVersionV1.parse(
            payload["maximumExclusive"], field_name=f"{field_name}.maximumExclusive"
        )
        if not minimum.precedes(maximum):
            raise ContractValidationError(f"{field_name} must be a non-empty version range.")
        return cls(minimum, maximum)

    def contains(self, version: SemanticVersionV1) -> bool:
        return not version.precedes(self.minimum_inclusive) and version.precedes(
            self.maximum_exclusive
        )


@dataclass(frozen=True, slots=True)
class OperatingSystemRangeV1:
    name: str
    architectures: tuple[str, ...]
    versions: VersionRangeV1


@dataclass(frozen=True, slots=True)
class PackCompatibilityV1:
    contracts: VersionRangeV1
    application: VersionRangeV1
    operating_systems: tuple[OperatingSystemRangeV1, ...]
    rollback: VersionRangeV1
    wire: Rfc8785JsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        validate_pack_schema_bounds_v1(value, definition="PackCompatibilityV1")
        payload = _exact_object(
            value,
            keys={
                "schemaVersion",
                "kind",
                "contracts",
                "application",
                "operatingSystems",
                "rollback",
            },
            field_name="packCompatibility",
        )
        _schema_and_kind(payload, kind="packCompatibility")
        operating_system_values = _require_list(
            payload["operatingSystems"], field_name="packCompatibility.operatingSystems"
        )
        if not operating_system_values:
            raise ContractValidationError("packCompatibility.operatingSystems must not be empty.")
        operating_systems: list[OperatingSystemRangeV1] = []
        platform_identities: set[tuple[str, str]] = set()
        for index, item in enumerate(operating_system_values):
            item_name = f"packCompatibility.operatingSystems[{index}]"
            item_payload = _exact_object(
                item,
                keys={
                    "name",
                    "architectures",
                    "minimumInclusive",
                    "maximumExclusive",
                },
                field_name=item_name,
            )
            name = _require_code(item_payload["name"], field_name=f"{item_name}.name")
            architectures = _require_unique_codes(
                item_payload["architectures"],
                field_name=f"{item_name}.architectures",
                allow_empty=False,
            )
            versions = VersionRangeV1.from_json_obj(
                {
                    "minimumInclusive": item_payload["minimumInclusive"],
                    "maximumExclusive": item_payload["maximumExclusive"],
                },
                field_name=item_name,
            )
            for architecture in architectures:
                identity = (name, architecture)
                if identity in platform_identities:
                    raise ContractValidationError(
                        "packCompatibility has a duplicate operating-system architecture range."
                    )
                platform_identities.add(identity)
            operating_systems.append(OperatingSystemRangeV1(name, architectures, versions))
        return cls(
            contracts=VersionRangeV1.from_json_obj(
                payload["contracts"], field_name="packCompatibility.contracts"
            ),
            application=VersionRangeV1.from_json_obj(
                payload["application"], field_name="packCompatibility.application"
            ),
            operating_systems=tuple(operating_systems),
            rollback=VersionRangeV1.from_json_obj(
                payload["rollback"], field_name="packCompatibility.rollback"
            ),
            wire=_freeze(payload),
        )


@dataclass(frozen=True, slots=True)
class PackDigestsV1:
    archive_sha256: str
    payload_tree_sha256: str
    sbom_sha256: str
    license_bundle_sha256: str
    conformance_receipt_sha256: str
    compatibility_contract_sha256: str


@dataclass(frozen=True, slots=True)
class PackDependencyV1:
    pack_id: str
    version: str

    @classmethod
    def from_json_obj(cls, value: object, *, field_name: str) -> Self:
        validate_pack_schema_bounds_v1(value, definition="PackDependencyV1")
        payload = _exact_object(value, keys={"packId", "version"}, field_name=field_name)
        return cls(
            _require_pack_id(payload["packId"], field_name=f"{field_name}.packId"),
            _require_version(payload["version"], field_name=f"{field_name}.version"),
        )


@dataclass(frozen=True, slots=True)
class SangrepPackManifestV1:
    pack_id: str
    version: str
    family: PackFamilyV1
    publisher_id: str
    channel: PackChannelV1
    compatibility: PackCompatibilityV1
    digests: PackDigestsV1
    dependencies: tuple[PackDependencyV1, ...]
    conformance_verdict: PackConformanceVerdictV1
    wire: Rfc8785JsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        validate_pack_schema_bounds_v1(value, definition="SangrepPackManifestV1")
        payload = _exact_object(
            value,
            keys={
                "schemaVersion",
                "kind",
                "packId",
                "version",
                "family",
                "publisher",
                "channel",
                "maturity",
                "limitations",
                "formats",
                "compatibility",
                "resources",
                "execution",
                "permissions",
                "dependencies",
                "payload",
                "provenance",
                "digests",
                "license",
                "conformance",
                "signature",
            },
            field_name="sangrepPackManifest",
        )
        _schema_and_kind(payload, kind="sangrepPackManifest")
        pack_id = _require_pack_id(payload["packId"], field_name="packId")
        version = _require_version(payload["version"], field_name="version")
        family = _require_enum(PackFamilyV1, payload["family"], field_name="family")
        publisher = _exact_object(
            payload["publisher"],
            keys={"publisherId", "trustTier"},
            field_name="publisher",
        )
        publisher_id = _require_pack_id(publisher["publisherId"], field_name="publisherId")
        _require_enum_value(
            publisher["trustTier"],
            values={"firstParty", "verifiedCommunity", "community"},
            field_name="trustTier",
        )
        channel = _require_enum(PackChannelV1, payload["channel"], field_name="channel")
        _require_enum_value(
            payload["maturity"],
            values={"reviewableExperimental", "previewable", "graduated"},
            field_name="maturity",
        )
        _require_unique_strings(payload["limitations"], field_name="limitations", allow_empty=False)
        _validate_formats(payload["formats"])
        compatibility = PackCompatibilityV1.from_json_obj(payload["compatibility"])
        _validate_resources(payload["resources"])
        execution_mode, entrypoint_ids = _validate_execution(payload["execution"])
        permission_ids, required_permission_ids = _validate_permissions(
            payload["permissions"], execution_mode=execution_mode
        )
        dependencies = _parse_dependencies(payload["dependencies"], owner_pack_id=pack_id)
        _validate_payload(
            payload["payload"],
            family=family,
            execution_mode=execution_mode,
            entrypoint_ids=entrypoint_ids,
        )
        if family is PackFamilyV1.PARSER and "source.read" not in required_permission_ids:
            raise ContractValidationError(
                "parser packs must declare required source.read permission."
            )
        _validate_provenance(payload["provenance"])
        digests = _parse_digests(payload["digests"])
        compatibility_digest = rfc8785_json_sha256_v1(
            cast(JsonValue, thaw_rfc8785_json_object_v1(compatibility.wire))
        )
        if digests.compatibility_contract_sha256 != compatibility_digest:
            raise ContractValidationError(
                "compatibilityContractSha256 does not match packCompatibility."
            )
        _validate_license(payload["license"])
        conformance_verdict, conformance_receipt = _validate_conformance(payload["conformance"])
        if conformance_receipt != digests.conformance_receipt_sha256:
            raise ContractValidationError(
                "conformanceReceiptSha256 does not match packConformance."
            )
        _validate_signature_binding(
            payload,
            pack_id=pack_id,
            version=version,
            family=family,
            publisher_id=publisher_id,
            channel=channel,
            digests=digests,
        )
        return cls(
            pack_id=pack_id,
            version=version,
            family=family,
            publisher_id=publisher_id,
            channel=channel,
            compatibility=compatibility,
            digests=digests,
            dependencies=dependencies,
            conformance_verdict=conformance_verdict,
            wire=_freeze(payload),
        )

    def to_json_obj(self) -> JsonObjectValue:
        return thaw_rfc8785_json_object_v1(self.wire)


@dataclass(frozen=True, slots=True)
class PackCatalogEntryV1:
    pack_id: str
    version: str
    family: PackFamilyV1
    manifest_sha256: str
    archive_sha256: str
    dependencies: tuple[PackDependencyV1, ...]

    @property
    def identity(self) -> tuple[str, str]:
        return (self.pack_id, self.version)


@dataclass(frozen=True, slots=True)
class SangrepPackCatalogV1:
    catalog_id: str
    version: str
    channel: PackChannelV1
    entries: tuple[PackCatalogEntryV1, ...]
    wire: Rfc8785JsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        validate_pack_schema_bounds_v1(value, definition="SangrepPackCatalogV1")
        payload = _exact_object(
            value,
            keys={"schemaVersion", "kind", "catalogId", "version", "channel", "entries"},
            field_name="sangrepPackCatalog",
        )
        _schema_and_kind(payload, kind="sangrepPackCatalog")
        entry_values = _require_list(payload["entries"], field_name="entries")
        entries: list[PackCatalogEntryV1] = []
        identities: set[tuple[str, str]] = set()
        for index, item in enumerate(entry_values):
            field_name = f"entries[{index}]"
            entry_payload = _exact_object(
                item,
                keys={
                    "packId",
                    "version",
                    "family",
                    "manifestUri",
                    "manifestSha256",
                    "archiveUri",
                    "archiveSha256",
                    "dependencies",
                },
                field_name=field_name,
            )
            pack_id = _require_pack_id(entry_payload["packId"], field_name=f"{field_name}.packId")
            version = _require_version(entry_payload["version"], field_name=f"{field_name}.version")
            _require_uri(entry_payload["manifestUri"], field_name=f"{field_name}.manifestUri")
            _require_uri(entry_payload["archiveUri"], field_name=f"{field_name}.archiveUri")
            entry = PackCatalogEntryV1(
                pack_id=pack_id,
                version=version,
                family=_require_enum(
                    PackFamilyV1,
                    entry_payload["family"],
                    field_name=f"{field_name}.family",
                ),
                manifest_sha256=require_sha256(
                    _require_string(
                        entry_payload["manifestSha256"],
                        field_name=f"{field_name}.manifestSha256",
                    ),
                    field_name=f"{field_name}.manifestSha256",
                ),
                archive_sha256=require_sha256(
                    _require_string(
                        entry_payload["archiveSha256"],
                        field_name=f"{field_name}.archiveSha256",
                    ),
                    field_name=f"{field_name}.archiveSha256",
                ),
                dependencies=_parse_dependencies(
                    entry_payload["dependencies"], owner_pack_id=pack_id
                ),
            )
            if entry.identity in identities:
                raise ContractValidationError("catalog contains a duplicate pack identity.")
            identities.add(entry.identity)
            entries.append(entry)
        available = {entry.identity for entry in entries}
        for entry in entries:
            for dependency in entry.dependencies:
                if (dependency.pack_id, dependency.version) not in available:
                    raise ContractValidationError(
                        "catalog dependency is not an exact catalog entry."
                    )
        return cls(
            catalog_id=_require_pack_id(payload["catalogId"], field_name="catalogId"),
            version=_require_version(payload["version"], field_name="version"),
            channel=_require_enum(PackChannelV1, payload["channel"], field_name="channel"),
            entries=tuple(entries),
            wire=_freeze(payload),
        )

    def to_json_obj(self) -> JsonObjectValue:
        return thaw_rfc8785_json_object_v1(self.wire)


def manifest_sha256_v1(manifest: SangrepPackManifestV1) -> str:
    return rfc8785_json_sha256_omitting_field_v1(manifest.to_json_obj(), field_name="signature")


def verify_manifest_artifact_digests_v1(
    manifest: SangrepPackManifestV1,
    *,
    archive_sha256: str,
    payload_tree_sha256: str,
    sbom_sha256: str,
    license_bundle_sha256: str,
    conformance_receipt_sha256: str,
) -> None:
    actual = {
        "archiveSha256": require_sha256(archive_sha256, field_name="archiveSha256"),
        "payloadTreeSha256": require_sha256(payload_tree_sha256, field_name="payloadTreeSha256"),
        "sbomSha256": require_sha256(sbom_sha256, field_name="sbomSha256"),
        "licenseBundleSha256": require_sha256(
            license_bundle_sha256, field_name="licenseBundleSha256"
        ),
        "conformanceReceiptSha256": require_sha256(
            conformance_receipt_sha256, field_name="conformanceReceiptSha256"
        ),
    }
    expected = {
        "archiveSha256": manifest.digests.archive_sha256,
        "payloadTreeSha256": manifest.digests.payload_tree_sha256,
        "sbomSha256": manifest.digests.sbom_sha256,
        "licenseBundleSha256": manifest.digests.license_bundle_sha256,
        "conformanceReceiptSha256": manifest.digests.conformance_receipt_sha256,
    }
    for field_name in expected:
        if actual[field_name] != expected[field_name]:
            raise ContractValidationError(f"{field_name} does not match the manifest digest.")


def verify_manifest_activation_v1(manifest: SangrepPackManifestV1) -> None:
    if manifest.conformance_verdict is not PackConformanceVerdictV1.PASSED:
        raise ContractValidationError("pack qualification verdict does not permit activation.")


def verify_manifest_compatibility_v1(
    manifest: SangrepPackManifestV1,
    *,
    contracts_version: str,
    application_version: str,
    operating_system: str,
    architecture: str,
    operating_system_version: str,
) -> None:
    contracts = SemanticVersionV1.parse(contracts_version, field_name="contracts version")
    application = SemanticVersionV1.parse(application_version, field_name="application version")
    os_version = SemanticVersionV1.parse(
        operating_system_version, field_name="operating system version"
    )
    if not manifest.compatibility.contracts.contains(contracts):
        raise ContractValidationError("contracts version is outside the compatible range.")
    if not manifest.compatibility.application.contains(application):
        raise ContractValidationError("application version is outside the compatible range.")
    for supported in manifest.compatibility.operating_systems:
        if supported.name == operating_system and architecture in supported.architectures:
            if supported.versions.contains(os_version):
                return
            raise ContractValidationError(
                "operating system version is outside the compatible range."
            )
    raise ContractValidationError("operating system or architecture is not compatible.")


def verify_catalog_dependency_graph_v1(catalog: SangrepPackCatalogV1) -> None:
    graph = {
        entry.identity: tuple((item.pack_id, item.version) for item in entry.dependencies)
        for entry in catalog.entries
    }
    visiting: set[tuple[str, str]] = set()
    visited: set[tuple[str, str]] = set()

    def visit(identity: tuple[str, str]) -> None:
        if identity in visiting:
            raise ContractValidationError("catalog contains a dependency cycle.")
        if identity in visited:
            return
        visiting.add(identity)
        for dependency in graph[identity]:
            visit(dependency)
        visiting.remove(identity)
        visited.add(identity)

    for identity in graph:
        visit(identity)


def _require_string(value: object, *, field_name: str) -> str:
    if type(value) is not str or not value:
        raise ContractValidationError(f"{field_name} must be a non-empty string.")
    return value


def _require_list(value: object, *, field_name: str) -> list[object]:
    if type(value) is not list:
        raise ContractValidationError(f"{field_name} must be a JSON array.")
    return value


def _exact_object(value: object, *, keys: set[str], field_name: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ContractValidationError(f"{field_name} must be a JSON object.")
    if set(value) != keys:
        raise ContractValidationError(f"{field_name} has missing or unknown fields.")
    return value


def _schema_and_kind(payload: dict[str, object], *, kind: str) -> None:
    if type(payload["schemaVersion"]) is not int or payload["schemaVersion"] != 1:
        raise ContractValidationError("schemaVersion must equal 1.")
    if type(payload["kind"]) is not str or payload["kind"] != kind:
        raise ContractValidationError(f"kind must equal {kind}.")


def _require_pack_id(value: object, *, field_name: str) -> str:
    text = _require_string(value, field_name=field_name)
    if len(text) > 128 or _PACK_ID.fullmatch(text) is None:
        raise ContractValidationError(f"{field_name} must be a lowercase pack identifier.")
    return text


def _require_code(value: object, *, field_name: str) -> str:
    text = _require_string(value, field_name=field_name)
    if len(text) > 128 or _CODE.fullmatch(text) is None:
        raise ContractValidationError(f"{field_name} must be a v1 code.")
    return text


def _require_version(value: object, *, field_name: str) -> str:
    text = _require_string(value, field_name=field_name)
    SemanticVersionV1.parse(text, field_name=field_name)
    return text


def _require_pack_relative_path(value: object, *, field_name: str) -> str:
    text = _require_string(value, field_name=field_name)
    if _RELATIVE_PATH.fullmatch(text) is None:
        raise ContractValidationError(f"{field_name} must be a safe relative path label.")
    try:
        return require_safe_relative_path_label_v1(
            text,
            is_root=False,
            field_name=field_name,
        )
    except ContractValidationError:
        raise ContractValidationError(f"{field_name} must be a safe relative path label.") from None


def _require_enum(
    enum_type: type[EnumType],
    value: object,
    *,
    field_name: str,
) -> EnumType:
    text = _require_string(value, field_name=field_name)
    try:
        return enum_type(text)
    except ValueError:
        raise ContractValidationError(f"{field_name} contains an unknown enum value.") from None


def _require_enum_value(value: object, *, values: set[str], field_name: str) -> str:
    text = _require_string(value, field_name=field_name)
    if text not in values:
        raise ContractValidationError(f"{field_name} contains an unknown enum value.")
    return text


def _require_unique_strings(
    value: object, *, field_name: str, allow_empty: bool
) -> tuple[str, ...]:
    values = _require_list(value, field_name=field_name)
    result = tuple(_require_string(item, field_name=field_name) for item in values)
    if not allow_empty and not result:
        raise ContractValidationError(f"{field_name} must not be empty.")
    if len(result) != len(set(result)):
        raise ContractValidationError(f"{field_name} contains a duplicate value.")
    return result


def _require_unique_codes(value: object, *, field_name: str, allow_empty: bool) -> tuple[str, ...]:
    values = _require_list(value, field_name=field_name)
    result = tuple(_require_code(item, field_name=field_name) for item in values)
    if not allow_empty and not result:
        raise ContractValidationError(f"{field_name} must not be empty.")
    if len(result) != len(set(result)):
        raise ContractValidationError(f"{field_name} contains a duplicate code.")
    return result


def _safe_int(value: object, *, field_name: str, positive: bool = False) -> int:
    minimum = 1 if positive else 0
    if type(value) is not int or value < minimum or value > MAX_SAFE_INTEGER:
        qualifier = "positive" if positive else "non-negative"
        raise ContractValidationError(f"{field_name} must be a safe {qualifier} integer.")
    return value


def _freeze(payload: dict[str, object]) -> Rfc8785JsonObjectV1:
    return freeze_rfc8785_json_object_v1(cast(JsonObjectValue, payload))


def _validate_formats(value: object) -> None:
    payload = _exact_object(value, keys={"supported", "unsupported"}, field_name="formats")
    supported = _require_unique_strings(
        payload["supported"], field_name="formats.supported", allow_empty=False
    )
    if any(_MEDIA_TYPE.fullmatch(item) is None for item in supported):
        raise ContractValidationError("formats.supported contains an invalid media type.")
    _require_unique_strings(
        payload["unsupported"], field_name="formats.unsupported", allow_empty=False
    )


def _validate_resources(value: object) -> None:
    payload = _exact_object(
        value,
        keys={
            "schemaVersion",
            "kind",
            "compressedSizeBytes",
            "installedSizeBytes",
            "expectedPeakMemoryBytes",
            "workerStartupProfile",
            "workerStartupTimeoutMs",
        },
        field_name="packResources",
    )
    _schema_and_kind(payload, kind="packResources")
    compressed = _safe_int(
        payload["compressedSizeBytes"], field_name="compressedSizeBytes", positive=True
    )
    installed = _safe_int(
        payload["installedSizeBytes"], field_name="installedSizeBytes", positive=True
    )
    if installed < compressed:
        raise ContractValidationError("installedSizeBytes must not be below compressedSizeBytes.")
    _safe_int(
        payload["expectedPeakMemoryBytes"],
        field_name="expectedPeakMemoryBytes",
        positive=True,
    )
    _require_enum_value(
        payload["workerStartupProfile"],
        values={"boundedSubprocess", "sharedRuntime"},
        field_name="workerStartupProfile",
    )
    _safe_int(
        payload["workerStartupTimeoutMs"],
        field_name="workerStartupTimeoutMs",
        positive=True,
    )


def _validate_execution(value: object) -> tuple[PackExecutionModeV1, frozenset[str]]:
    payload = _exact_object(
        value,
        keys={"mode", "isolationProfile", "entrypoints"},
        field_name="execution",
    )
    mode_text = _require_string(payload["mode"], field_name="execution.mode")
    try:
        mode = PackExecutionModeV1(mode_text)
    except ValueError:
        raise ContractValidationError("execution.mode contains an unknown enum value.") from None
    isolation_profile = _require_enum_value(
        payload["isolationProfile"],
        values={"processSandboxV1", "remoteServiceV1", "hybridProcessV1"},
        field_name="execution.isolationProfile",
    )
    required_isolation = {
        PackExecutionModeV1.LOCAL: "processSandboxV1",
        PackExecutionModeV1.REMOTE: "remoteServiceV1",
        PackExecutionModeV1.HYBRID: "hybridProcessV1",
    }[mode]
    if isolation_profile != required_isolation:
        raise ContractValidationError(f"{mode.value} mode requires {required_isolation}.")
    entrypoints: set[str] = set()
    for index, item in enumerate(
        _require_list(payload["entrypoints"], field_name="execution.entrypoints")
    ):
        field_name = f"execution.entrypoints[{index}]"
        entrypoint = _exact_object(
            item,
            keys={"entrypointId", "relativeExecutablePath", "protocol", "arguments"},
            field_name=field_name,
        )
        entrypoint_id = _require_code(
            entrypoint["entrypointId"], field_name=f"{field_name}.entrypointId"
        )
        _require_pack_relative_path(
            entrypoint["relativeExecutablePath"],
            field_name=f"{field_name}.relativeExecutablePath",
        )
        _require_enum_value(
            entrypoint["protocol"],
            values={"sangrepPackWorkerV1"},
            field_name=f"{field_name}.protocol",
        )
        _require_unique_strings(
            entrypoint["arguments"], field_name=f"{field_name}.arguments", allow_empty=True
        )
        if entrypoint_id in entrypoints:
            raise ContractValidationError("execution contains a duplicate entrypointId.")
        entrypoints.add(entrypoint_id)
    if not entrypoints:
        raise ContractValidationError("execution.entrypoints must not be empty.")
    return mode, frozenset(entrypoints)


def _validate_permissions(
    value: object,
    *,
    execution_mode: PackExecutionModeV1,
) -> tuple[frozenset[str], frozenset[str]]:
    payload = _exact_object(
        value,
        keys={"sourceDataClasses", "grants", "network", "provider", "userConsent"},
        field_name="permissions",
    )
    _require_unique_codes(
        payload["sourceDataClasses"],
        field_name="permissions.sourceDataClasses",
        allow_empty=False,
    )
    permission_ids: set[str] = set()
    required_permission_ids: set[str] = set()
    for index, item in enumerate(_require_list(payload["grants"], field_name="permissions.grants")):
        field_name = f"permissions.grants[{index}]"
        grant = _exact_object(
            item,
            keys={"permission", "required", "reason"},
            field_name=field_name,
        )
        permission = _require_enum_value(
            grant["permission"],
            values={
                "source.read",
                "temporaryStorage.write",
                "network.connect",
                "provider.invoke",
            },
            field_name=f"{field_name}.permission",
        )
        if type(grant["required"]) is not bool:
            raise ContractValidationError(f"{field_name}.required must be a boolean.")
        if grant["required"]:
            required_permission_ids.add(permission)
        _require_string(grant["reason"], field_name=f"{field_name}.reason")
        if permission in permission_ids:
            raise ContractValidationError("permissions.grants contains a duplicate permission.")
        permission_ids.add(permission)
    if execution_mode in {PackExecutionModeV1.REMOTE, PackExecutionModeV1.HYBRID}:
        for required in ("network.connect", "provider.invoke"):
            if required not in required_permission_ids:
                raise ContractValidationError(
                    f"{execution_mode.value} packs must declare required {required} permission."
                )
        network = _exact_object(
            payload["network"],
            keys={"destinations", "retention", "region"},
            field_name="permissions.network",
        )
        destinations = _require_unique_strings(
            network["destinations"],
            field_name="permissions.network.destinations",
            allow_empty=False,
        )
        if any(_HOST.fullmatch(item) is None for item in destinations):
            raise ContractValidationError("permissions.network has an invalid destination.")
        _require_string(network["retention"], field_name="permissions.network.retention")
        _require_string(network["region"], field_name="permissions.network.region")
        provider = _exact_object(
            payload["provider"],
            keys={"providerId", "costModel"},
            field_name="permissions.provider",
        )
        _require_pack_id(provider["providerId"], field_name="permissions.provider.providerId")
        _require_string(provider["costModel"], field_name="permissions.provider.costModel")
        _require_enum_value(
            payload["userConsent"], values={"required"}, field_name="permissions.userConsent"
        )
    else:
        forbidden_permissions = permission_ids & {"network.connect", "provider.invoke"}
        if forbidden_permissions:
            raise ContractValidationError(
                "local packs must not declare network.connect or provider.invoke permission."
            )
        if payload["network"] is not None or payload["provider"] is not None:
            raise ContractValidationError(
                "local packs must not declare network or provider policy."
            )
        _require_enum_value(
            payload["userConsent"],
            values={"notRequired", "required"},
            field_name="permissions.userConsent",
        )
    return frozenset(permission_ids), frozenset(required_permission_ids)


def _parse_dependencies(value: object, *, owner_pack_id: str) -> tuple[PackDependencyV1, ...]:
    dependencies = tuple(
        PackDependencyV1.from_json_obj(item, field_name=f"dependencies[{index}]")
        for index, item in enumerate(_require_list(value, field_name="dependencies"))
    )
    identities = {(item.pack_id, item.version) for item in dependencies}
    if len(identities) != len(dependencies):
        raise ContractValidationError("dependencies contains a duplicate exact version.")
    if any(item.pack_id == owner_pack_id for item in dependencies):
        raise ContractValidationError("a pack cannot depend on itself.")
    return dependencies


def _validate_payload(
    value: object,
    *,
    family: PackFamilyV1,
    execution_mode: PackExecutionModeV1,
    entrypoint_ids: frozenset[str],
) -> None:
    if family is PackFamilyV1.PARSER:
        payload = _exact_object(
            value,
            keys={
                "schemaVersion",
                "kind",
                "maximumInputBytes",
                "outputContract",
                "locatorContract",
                "entrypointId",
            },
            field_name="parserPack",
        )
        _schema_and_kind(payload, kind="parserPack")
        if execution_mode is not PackExecutionModeV1.LOCAL:
            raise ContractValidationError("parserPack execution mode must be local.")
        _safe_int(payload["maximumInputBytes"], field_name="maximumInputBytes", positive=True)
        _require_code(payload["outputContract"], field_name="outputContract")
        _require_code(payload["locatorContract"], field_name="locatorContract")
    else:
        payload = _exact_object(
            value,
            keys={
                "schemaVersion",
                "kind",
                "projectionContract",
                "resultContract",
                "receiptContract",
                "entrypointId",
            },
            field_name="intelligencePack",
        )
        _schema_and_kind(payload, kind="intelligencePack")
        _require_code(payload["projectionContract"], field_name="projectionContract")
        _require_code(payload["resultContract"], field_name="resultContract")
        _require_code(payload["receiptContract"], field_name="receiptContract")
    entrypoint_id = _require_code(payload["entrypointId"], field_name="entrypointId")
    if entrypoint_id not in entrypoint_ids:
        raise ContractValidationError("payload entrypointId is not declared by execution.")


def _validate_provenance(value: object) -> None:
    payload = _exact_object(
        value,
        keys={"kind", "uri", "revision", "buildReceiptSha256"},
        field_name="provenance",
    )
    _require_enum_value(
        payload["kind"], values={"sourceArchive", "buildReceipt"}, field_name="provenance.kind"
    )
    _require_uri(payload["uri"], field_name="provenance.uri")
    _require_string(payload["revision"], field_name="provenance.revision")
    require_sha256(
        _require_string(payload["buildReceiptSha256"], field_name="buildReceiptSha256"),
        field_name="buildReceiptSha256",
    )


def _require_uri(value: object, *, field_name: str) -> str:
    text = _require_string(value, field_name=field_name)
    if not text.startswith("https://") or any(character.isspace() for character in text):
        raise ContractValidationError(f"{field_name} must be an HTTPS URI.")
    return text


def _parse_digests(value: object) -> PackDigestsV1:
    keys = {
        "archiveSha256",
        "payloadTreeSha256",
        "sbomSha256",
        "licenseBundleSha256",
        "conformanceReceiptSha256",
        "compatibilityContractSha256",
    }
    payload = _exact_object(value, keys=keys, field_name="digests")

    def digest(name: str) -> str:
        return require_sha256(_require_string(payload[name], field_name=name), field_name=name)

    return PackDigestsV1(
        archive_sha256=digest("archiveSha256"),
        payload_tree_sha256=digest("payloadTreeSha256"),
        sbom_sha256=digest("sbomSha256"),
        license_bundle_sha256=digest("licenseBundleSha256"),
        conformance_receipt_sha256=digest("conformanceReceiptSha256"),
        compatibility_contract_sha256=digest("compatibilityContractSha256"),
    )


def _validate_license(value: object) -> None:
    payload = _exact_object(
        value,
        keys={"expression", "noticePath", "licensePaths"},
        field_name="license",
    )
    _require_string(payload["expression"], field_name="license.expression")
    _require_pack_relative_path(payload["noticePath"], field_name="license.noticePath")
    paths = _require_unique_strings(
        payload["licensePaths"], field_name="license.licensePaths", allow_empty=False
    )
    for path in paths:
        _require_pack_relative_path(path, field_name="license.licensePaths")


def _validate_conformance(value: object) -> tuple[PackConformanceVerdictV1, str]:
    payload = _exact_object(
        value,
        keys={"schemaVersion", "kind", "suiteId", "suiteVersion", "verdict", "receiptSha256"},
        field_name="packConformance",
    )
    _schema_and_kind(payload, kind="packConformance")
    _require_pack_id(payload["suiteId"], field_name="suiteId")
    _require_version(payload["suiteVersion"], field_name="suiteVersion")
    verdict_text = _require_string(payload["verdict"], field_name="verdict")
    try:
        verdict = PackConformanceVerdictV1(verdict_text)
    except ValueError:
        raise ContractValidationError("verdict contains an unknown enum value.") from None
    receipt = require_sha256(
        _require_string(payload["receiptSha256"], field_name="receiptSha256"),
        field_name="receiptSha256",
    )
    return verdict, receipt


def _validate_signature_binding(
    manifest_payload: dict[str, object],
    *,
    pack_id: str,
    version: str,
    family: PackFamilyV1,
    publisher_id: str,
    channel: PackChannelV1,
    digests: PackDigestsV1,
) -> None:
    signature = _exact_object(
        manifest_payload["signature"],
        keys={
            "schemaVersion",
            "kind",
            "suite",
            "role",
            "keyId",
            "unsignedEnvelope",
            "signatureBase64",
        },
        field_name="sangrepPackSignature",
    )
    _schema_and_kind(signature, kind="sangrepPackSignature")
    _require_enum_value(signature["suite"], values={"Ed25519"}, field_name="suite")
    _require_enum_value(signature["role"], values={"packPublisher"}, field_name="role")
    key_id = _require_string(signature["keyId"], field_name="keyId")
    if _KEY_ID.fullmatch(key_id) is None:
        raise ContractValidationError("keyId must be an Ed25519 SHA-256 key ID.")
    _require_canonical_base64(
        signature["signatureBase64"], field_name="signatureBase64", decoded_bytes=64
    )
    envelope = _exact_object(
        signature["unsignedEnvelope"],
        keys={
            "schemaVersion",
            "kind",
            "packId",
            "version",
            "family",
            "publisherId",
            "channel",
            "manifestSha256",
            "archiveSha256",
            "payloadTreeSha256",
            "sbomSha256",
            "licenseBundleSha256",
            "conformanceReceiptSha256",
            "compatibilityContractSha256",
        },
        field_name="sangrepPackUnsignedEnvelope",
    )
    _schema_and_kind(envelope, kind="sangrepPackUnsignedEnvelope")
    identity = {
        "packId": pack_id,
        "version": version,
        "family": family.value,
        "publisherId": publisher_id,
        "channel": channel.value,
    }
    for field_name, expected in identity.items():
        if envelope[field_name] != expected:
            raise ContractValidationError(
                f"unsignedEnvelope.{field_name} does not match the manifest."
            )
    digest_identity = {
        "archiveSha256": digests.archive_sha256,
        "payloadTreeSha256": digests.payload_tree_sha256,
        "sbomSha256": digests.sbom_sha256,
        "licenseBundleSha256": digests.license_bundle_sha256,
        "conformanceReceiptSha256": digests.conformance_receipt_sha256,
        "compatibilityContractSha256": digests.compatibility_contract_sha256,
    }
    for field_name, expected in digest_identity.items():
        actual = require_sha256(
            _require_string(envelope[field_name], field_name=field_name),
            field_name=field_name,
        )
        if actual != expected:
            raise ContractValidationError(
                f"unsignedEnvelope.{field_name} does not match the manifest."
            )
    expected_manifest_sha256 = rfc8785_json_sha256_omitting_field_v1(
        cast(JsonObjectValue, manifest_payload), field_name="signature"
    )
    actual_manifest_sha256 = require_sha256(
        _require_string(envelope["manifestSha256"], field_name="manifestSha256"),
        field_name="manifestSha256",
    )
    if actual_manifest_sha256 != expected_manifest_sha256:
        raise ContractValidationError("manifestSha256 does not match the unsigned manifest.")


def _require_canonical_base64(value: object, *, field_name: str, decoded_bytes: int) -> bytes:
    text = _require_string(value, field_name=field_name)
    try:
        decoded = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ContractValidationError(f"{field_name} must be strict canonical base64.") from error
    if len(decoded) != decoded_bytes or base64.b64encode(decoded).decode("ascii") != text:
        raise ContractValidationError(f"{field_name} must be strict canonical base64.")
    return decoded
