# Copyright 2026 SURF.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Sealed-secret form fields: never store cleartext secrets in the database.

A sealed-secret field renders as a normal password box in the UI, but its value is Fernet-encrypted
during ``post_form`` validation, so only ciphertext (``fernet-v1:<kid>:<token>`` envelopes) ever reaches
``input_states``, ``process_steps.state`` or resource values. Decryption happens server-side only, inside
workflow steps, via :func:`decrypt_sealed_secret`.

This module also hosts the log-redaction helpers. Raw ``user_inputs`` are logged on validation failure
(``services/processes.py``), which would persist cleartext into the log pipeline. Redaction masks *only*
the values of sealed-secret fields, leaving every other field untouched for debuggability.
"""

import re
from collections.abc import Generator, Iterable
from copy import deepcopy
from typing import Any, get_args

import structlog
from pydantic import BaseModel

logger = structlog.get_logger(__name__)

SEALED_SECRET_FORMAT = "sealedSecret"  # noqa: S105 - JSON-schema format marker, not a credential
"""JSON-schema ``format`` marker identifying a sealed-secret field."""

SEALED_ENVELOPE_VERSION = "fernet-v1"
"""Envelope version prefix. Bump when the crypto construction changes; old envelopes keep decrypting."""

SEALED_ENVELOPE_RE = re.compile(r"^fernet-v1:[0-9a-f]{8}:[A-Za-z0-9\-_]+={0,2}$")
"""Matches a well-formed sealed envelope. Anchored: cleartext never matches by accident."""

SEALED_REDACTED = "***REDACTED***"
"""Placeholder substituted for cleartext secrets in logs. Never a valid envelope (no version prefix)."""

SEALED_SUMMARY_MASK = "••••••"
"""Placeholder rendered for sealed values in summary tables. Never echoed, never decryptable."""

_MAX_GENERATOR_PAGES = 25
"""Upper bound when walking a form generator for redaction. Guards against pathological generators."""


def is_sealed_envelope(value: object) -> bool:
    """Return True when ``value`` is a well-formed sealed envelope (ciphertext, safe to log/index).

    Args:
        value: The value to inspect. Only strings can be envelopes.

    Returns:
        True for ``fernet-v1:<kid>:<token>`` strings, False for everything else (including cleartext).
    """
    return isinstance(value, str) and SEALED_ENVELOPE_RE.match(value) is not None


def _field_format(json_schema_extra: Any) -> str | None:
    """Return the ``format`` key a field's ``json_schema_extra`` renders as, dict- or callable-based."""
    if isinstance(json_schema_extra, dict):
        format_value = json_schema_extra.get("format")
        return format_value if isinstance(format_value, str) else None
    if callable(json_schema_extra):
        try:
            schema: dict[str, Any] = {}
            json_schema_extra(schema)
        except Exception:  # noqa: BLE001 - best effort inspection; unresolvable extras are simply not sealed
            return None
        format_value = schema.get("format")
        return format_value if isinstance(format_value, str) else None
    return None


def _sealed_fields_of_model(model_cls: Any, *, _seen: set[Any] | None = None) -> set[str]:
    """Collect sealed-secret field names from a form/model class, recursing into nested models.

    Args:
        model_cls: A pydantic model class (anything else yields nothing).
        _seen: Classes already visited (cycle guard for recursive models).

    Returns:
        Field names whose schema carries ``format: sealedSecret``.
    """
    seen = _seen if _seen is not None else set()
    if not (isinstance(model_cls, type) and issubclass(model_cls, BaseModel)) or model_cls in seen:
        return set()
    seen.add(model_cls)

    names: set[str] = set()
    for name, field in model_cls.model_fields.items():
        if _field_format(field.json_schema_extra) == SEALED_SECRET_FORMAT or _has_direct_marker(field.annotation):
            names.add(name)
        for nested in _iter_nested_models(field.annotation):
            names.update(_sealed_fields_of_model(nested, _seen=seen))
    return names


def _iter_nested_models(annotation: Any) -> Generator[Any, None, None]:
    """Yield pydantic model classes nested inside an annotation (unions, optionals, lists, dicts)."""
    if annotation is None:
        return
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        yield annotation
        return
    for arg in get_args(annotation):
        yield from _iter_nested_models(arg)


def _has_direct_marker(annotation: Any) -> bool:
    """Return True when the annotation itself (or a union/list wrapper around it) is sealed-marked.

    Unlike :func:`is_sealed_secret_annotation`, this does not descend into nested model classes, so a
    field holding a model that merely *contains* a sealed field is not itself treated as sealed.
    """
    if annotation is None:
        return False
    metadata = getattr(annotation, "__metadata__", ())
    if any(_field_format(getattr(meta, "json_schema_extra", None)) == SEALED_SECRET_FORMAT for meta in metadata):
        return True
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return False
    return any(_has_direct_marker(arg) for arg in get_args(annotation))


def is_sealed_secret_annotation(annotation: Any) -> bool:
    """Return True when a type annotation (or anything nested in it) carries the sealed-secret marker.

    Used by the search indexer to skip sealed values: walks unions/optionals/lists/dicts and inspects
    ``Annotated`` metadata for ``json_schema_extra`` with ``format: sealedSecret``.

    Args:
        annotation: A (possibly complex) type annotation, e.g. from ``FieldInfo.annotation``.

    Returns:
        True if the annotation itself or any nested model field is sealed-secret marked.
    """
    if annotation is None:
        return False
    metadata = getattr(annotation, "__metadata__", ())
    if any(_field_format(getattr(meta, "json_schema_extra", None)) == SEALED_SECRET_FORMAT for meta in metadata):
        return True
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return bool(_sealed_fields_of_model(annotation))
    return any(is_sealed_secret_annotation(arg) for arg in get_args(annotation))


def sealed_field_names(
    form_generator: Any | None, state: dict[str, Any], user_inputs: Iterable[dict[str, Any]] | None = None
) -> tuple[frozenset[str], bool]:
    """Best-effort collection of sealed-secret field names for the current form.

    Drives the form generator *without validating anything*: yielded page classes are inspected for the
    ``sealedSecret`` format marker. Raw page dicts are fed back in so conditional generators advance;
    any failure part-way still keeps the names collected so far.

    Args:
        form_generator: The workflow's input-form generator (or a single form class, or None).
        state: Current workflow state, passed to the generator as ``post_form`` would.
        user_inputs: Raw per-page input dicts, fed back to advance conditional generators.

    Returns:
        A ``(names, resolved)`` pair. ``resolved`` is False only when even the first page could not be
        obtained (generator raised immediately); callers must then omit values from logs rather than
        risk leaking cleartext. An empty-but-resolved result authoritatively means "no sealed fields".
    """
    if form_generator is None:
        return frozenset(), True
    if isinstance(form_generator, type):
        return frozenset(_sealed_fields_of_model(form_generator)), True
    if not callable(form_generator):
        return frozenset(), False

    pages = list(user_inputs) if user_inputs else []
    names: set[str] = set()
    try:
        iterator = form_generator(state)
        if not hasattr(iterator, "send"):
            return frozenset(_sealed_fields_of_model(iterator)), True
        yielded: Any = next(iterator)
    except Exception:  # noqa: BLE001 - redaction is best effort; unresolvable forms omit values downstream
        logger.debug("Could not resolve sealed field names from form generator")
        return frozenset(), False

    resolved = True
    try:
        for index in range(_MAX_GENERATOR_PAGES):
            names.update(_sealed_fields_of_model(yielded))
            data = pages[index] if index < len(pages) else {}
            try:
                yielded = iterator.send(data)
            except StopIteration:
                break
    except Exception:  # noqa: BLE001 - keep names collected so far; still resolved
        logger.debug("Form generator walk ended early; using sealed field names collected so far")
    return frozenset(names), resolved


def _mask_leaf(value: Any) -> Any:
    """Mask a single value if it is a cleartext secret; leave envelopes, blanks and non-strings alone."""
    if value is None or value == "" or is_sealed_envelope(value):
        return value
    if isinstance(value, str):
        return SEALED_REDACTED
    return value


def _mask_subtree(value: Any) -> Any:
    """Mask every string leaf under a sealed key: the whole subtree counts as secret."""
    if isinstance(value, dict):
        return {key: _mask_subtree(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_mask_subtree(item) for item in value]
    return _mask_leaf(value)


def _mask_node(node: Any, names: frozenset[str]) -> Any:
    """Mask sealed-key values in a structure, recursing into non-sealed containers by field name."""
    if isinstance(node, dict):
        return {
            key: (_mask_subtree(value) if key in names else _mask_node(value, names)) for key, value in node.items()
        }
    if isinstance(node, list):
        return [_mask_node(item, names) for item in node]
    return node


def mask_sealed_cleartext(pages: list[dict[str, Any]] | None, names: frozenset[str]) -> list[dict[str, Any]]:
    """Return a deep copy of per-page inputs with cleartext sealed values replaced.

    Args:
        pages: Raw per-page input dicts (never mutated).
        names: Sealed field names from :func:`sealed_field_names`.

    Returns:
        Copied pages where every non-empty, non-envelope string under a sealed key — at any depth —
        is ``***REDACTED***``. All other fields, ``None``/``""`` keep-markers and valid envelopes pass
        through untouched.
    """
    if not pages:
        return []
    if not names:
        return deepcopy(pages)
    return [_mask_node(deepcopy(page), names) for page in pages]


def redacted_user_inputs(
    form_generator: Any | None, state: dict[str, Any], user_inputs: list[dict[str, Any]] | None
) -> list[dict[str, Any]] | dict[str, str]:
    """Log-safe copy of ``user_inputs``: only cleartext sealed values are masked, nothing else.

    When sealed field names cannot be resolved (generator raised immediately), values are omitted
    entirely rather than risk leaking cleartext — the safe direction. Runs on the validation-error
    path only, never on the hot path.

    Args:
        form_generator: The workflow's input-form generator, as passed to ``post_form``.
        state: The state passed to ``post_form`` alongside the generator.
        user_inputs: Raw per-page input dicts from the request.

    Returns:
        Masked per-page inputs, or ``{"omitted": ...}`` when the form could not be resolved.
    """
    if not user_inputs:
        return []
    names, resolved = sealed_field_names(form_generator, state, user_inputs)
    if not resolved:
        return {"omitted": "unresolved form schema"}
    return mask_sealed_cleartext(user_inputs, names)
