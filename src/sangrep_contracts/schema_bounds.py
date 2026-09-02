"""Dependency-free enforcement of generated JSON Schema length and item bounds."""

from __future__ import annotations

from collections.abc import Iterator

from .canonical import ContractValidationError
from .generated.pack_bounds_v1 import PACK_BOUND_RULES_V1


def _selected_values(
    value: object,
    path: tuple[str, ...],
    *,
    field_name: str,
) -> Iterator[tuple[object, str]]:
    if not path:
        yield value, field_name
        return
    selector, *remaining = path
    tail = tuple(remaining)
    if selector == "*":
        if type(value) is not list:
            return
        for index, item in enumerate(value):
            yield from _selected_values(
                item,
                tail,
                field_name=f"{field_name}[{index}]",
            )
        return
    if type(value) is not dict or selector not in value:
        return
    child_name = f"{field_name}.{selector}" if field_name else selector
    yield from _selected_values(value[selector], tail, field_name=child_name)


def validate_pack_schema_bounds_v1(value: object, *, definition: str) -> None:
    rules = PACK_BOUND_RULES_V1.get(definition)
    if rules is None:
        raise ContractValidationError("generated schema bound definition is unavailable.")
    for path, min_length, max_length, min_items, max_items in rules:
        for selected, field_name in _selected_values(value, path, field_name=definition):
            if type(selected) is str:
                length = len(selected)
                if min_length is not None and length < min_length:
                    raise ContractValidationError(
                        f"{field_name} is below its schema string-length minimum."
                    )
                if max_length is not None and length > max_length:
                    raise ContractValidationError(
                        f"{field_name} exceeds its schema string-length maximum."
                    )
            if type(selected) is list:
                length = len(selected)
                if min_items is not None and length < min_items:
                    raise ContractValidationError(
                        f"{field_name} is below its schema item-count minimum."
                    )
                if max_items is not None and length > max_items:
                    raise ContractValidationError(
                        f"{field_name} exceeds its schema item-count maximum."
                    )


__all__ = ("validate_pack_schema_bounds_v1",)
