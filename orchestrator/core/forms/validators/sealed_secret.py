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
the values of sealed-secret fields, leaving every other field untouched for debuggability; when the
form's sealed fields cannot be fully resolved, the values are omitted from the log entirely.
"""

import binascii
import re
from base64 import urlsafe_b64decode
from collections.abc import Generator, Iterable
from copy import deepcopy
from enum import Enum
from hashlib import sha256
from typing import Annotated, Any, get_args

import structlog
from cryptography.fernet import Fernet, InvalidToken
from pydantic import BaseModel, BeforeValidator, Field
from pydantic_core import PydanticCustomError

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

MAX_SEALED_PLAINTEXT_BYTES = 4096
"""Largest accepted cleartext secret (UTF-8 bytes). Bounds DB row, RAM and log-pipeline exposure."""

MAX_STORED_ENVELOPE_CHARS = 10000
"""Storage cap for a rendered envelope. Mirrors ``SubscriptionInstanceValueTable.value``
(``String(RESOURCE_VALUE_LENGTH)``) so a minted envelope can never overflow the column; the
4096-byte plaintext cap keeps every Fernet envelope (base64 overhead + prefix) well below it.
"""


class SealedSecretsDisabledError(ValueError):
    """Raised when a form uses SealedSecret but no Fernet key is configured.

    Failing closed is deliberate: silently storing plaintext would violate the core guarantee.
    """


class SealedSecretDecryptionError(ValueError):
    """Raised when an envelope cannot be decrypted with any configured key. Never carries the value."""


def _configured_fernets() -> list[tuple[str, Fernet]]:
    """Build (kid, Fernet) pairs from settings, newest first. Imported lazily to avoid import cycles."""
    from orchestrator.core.settings import app_settings

    pairs = []
    for key in app_settings.SEALED_SECRETS_FERNET_KEYS:
        raw = key.get_secret_value().encode()
        kid = sha256(_fernet_key_bytes(raw)).hexdigest()[:8]
        pairs.append((kid, Fernet(raw)))
    return pairs


def _fernet_key_bytes(raw: bytes) -> bytes:
    """Decode a Fernet key to its 32 raw bytes (raises on invalid keys, which settings validation prevents)."""
    return urlsafe_b64decode(raw)


def key_id_for_fernet_key(raw_key: str) -> str:
    """Derive the 8-hex envelope key id for a configured Fernet key string."""
    return sha256(_fernet_key_bytes(raw_key.encode())).hexdigest()[:8]


def encrypt_sealed_secret(plaintext: str) -> str:
    """Fernet-encrypt ``plaintext`` and wrap it in a versioned envelope.

    Args:
        plaintext: The cleartext secret (bounded by :data:`MAX_SEALED_PLAINTEXT_BYTES`).

    Returns:
        A ``fernet-v1:<kid>:<token>`` envelope string, safe for JSONB/String storage.

    Raises:
        SealedSecretsDisabledError: When no Fernet key is configured.
        ValueError: When the plaintext exceeds the size cap, or the minted envelope would not fit
            the storage column.
    """
    encoded = plaintext.encode("utf-8")
    if len(encoded) > MAX_SEALED_PLAINTEXT_BYTES:
        raise ValueError(f"Sealed secret exceeds {MAX_SEALED_PLAINTEXT_BYTES} bytes")
    pairs = _configured_fernets()
    if not pairs:
        raise SealedSecretsDisabledError(
            "Sealed secrets are disabled (SEALED_SECRETS_FERNET_KEYS is empty); refusing to store plaintext"
        )
    kid, fernet = pairs[0]
    envelope = f"{SEALED_ENVELOPE_VERSION}:{kid}:{fernet.encrypt(encoded).decode()}"
    # Storage-bound assertion: a minted envelope must fit the String column it is written to.
    # Unreachable with the 4096-byte plaintext cap today, so raise rather than truncate.
    if len(envelope) > MAX_STORED_ENVELOPE_CHARS:
        raise ValueError(f"Sealed envelope exceeds {MAX_STORED_ENVELOPE_CHARS} characters")
    return envelope


def decrypt_sealed_secret(envelope: str) -> str:
    """Decrypt a sealed envelope with the newest matching key.

    Args:
        envelope: A ``fernet-v1:<kid>:<token>`` string.

    Returns:
        The cleartext secret. Callers must use it immediately (e.g. a device API call) and never
        log it or return it into workflow state.

    Raises:
        SealedSecretDecryptionError: On malformed envelopes, unknown key ids or invalid tokens.
    """
    pairs = _configured_fernets()
    if not pairs:
        raise SealedSecretDecryptionError("Sealed secrets are disabled")
    try:
        version, kid, token = envelope.split(":", 2)
    except ValueError:
        raise SealedSecretDecryptionError("Malformed sealed envelope") from None
    if version != SEALED_ENVELOPE_VERSION or not token:
        raise SealedSecretDecryptionError("Unsupported sealed envelope version")
    ordered = sorted(pairs, key=lambda pair: 0 if pair[0] == kid else 1)
    for _, fernet in ordered:
        try:
            plaintext = fernet.decrypt(token.encode())
        except (InvalidToken, binascii.Error, ValueError):
            continue
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            continue
    raise SealedSecretDecryptionError("Cannot decrypt sealed secret with any configured key")


def resolve_sealed_secret_update(incoming: str | None, stored_envelope: str | None) -> str | None:
    """Apply modify-workflow keep-vs-rotate semantics.

    Args:
        incoming: Validated form value (``None`` means "keep"; ``""`` is tolerated as keep for
            non-validated paths, though the validator itself rejects empty strings loudly).
        stored_envelope: Envelope currently persisted (subscription value or prior state).

    Returns:
        The envelope to persist: ``stored_envelope`` on blank, ``incoming`` on rotate.
    """
    if not incoming:
        return stored_envelope
    return incoming


def _validate_sealed_secret(value: Any) -> Any:
    """Pydantic ``BeforeValidator``.

    ``None`` passes through (keep), current-kid envelopes pass through (no churn), old-kid
    envelopes are conditionally migrated (decrypt with the ring, re-encrypt to the newest key),
    cleartext encrypts. Runs during ``post_form`` validation, before anything is stored. Empty
    strings are rejected with an actionable error instead of being silently kept: pydantic feeds
    union members the *original* input, so a member-local ``""``-to-``None`` mapping could never
    make ``SealedSecret | None`` accept ``""``. The keep semantic is therefore ``null``/omitted
    (which the UI submits for blank fields); ``""`` fails loudly rather than risking an ambiguous
    store. Non-string inputs fail loudly (closes bytes/enum coercion).

    Envelope migration mirrors :func:`orchestrator.core.services.sealed_secrets.rewrap_envelope`
    (kid == target skip, decrypt -> encrypt -> verify); kept inline with a lazy import to avoid a
    validator <-> service import cycle. Future KMS backends only need to change the
    decrypt/encrypt helpers behind this seam (comment only, no abstraction today per YAGNI).
    """
    if value is None:
        return None
    if value == "":
        raise PydanticCustomError(
            "sealed_secret_blank",
            "Blank sealed secrets must be submitted as null (keep the stored value); empty strings are rejected",
        )
    if isinstance(value, Enum) or not isinstance(value, str):
        raise PydanticCustomError(
            "sealed_secret_type",
            "Sealed secret must be a string (cleartext) or a sealed envelope; got {actual}",
            {"actual": type(value).__name__},
        )
    if is_sealed_envelope(value):
        # Lazy import: services.sealed_secrets imports from this module (decrypt/encrypt helpers).
        from orchestrator.core.services.sealed_secrets import current_kid, envelope_kid

        target = current_kid()
        if target is None:
            raise PydanticCustomError(
                "sealed_secret_undecryptable",
                "Sealed secrets are disabled (no Fernet key configured); cannot accept stored envelopes",
            )
        kid = envelope_kid(value)
        if kid == target:
            return value
        try:
            plaintext = decrypt_sealed_secret(value)
        except SealedSecretDecryptionError as exc:
            raise PydanticCustomError(
                "sealed_secret_undecryptable",
                "Stored sealed envelope cannot be decrypted with any configured key",
            ) from exc
        fresh = encrypt_sealed_secret(plaintext)
        if decrypt_sealed_secret(fresh) != plaintext:
            raise PydanticCustomError(
                "sealed_secret_undecryptable",
                "Sealed envelope rewrap round-trip verification failed",
            )
        return fresh
    return encrypt_sealed_secret(value)


SealedSecret = Annotated[
    str,
    Field(json_schema_extra={"format": SEALED_SECRET_FORMAT, "writeOnly": True}),
    BeforeValidator(_validate_sealed_secret),
]
"""Secret form field: password widget in the UI, Fernet envelope in the DB.

Declare required secrets as ``field: SealedSecret`` (blank and null are rejected) and modify-workflow
secrets as ``field: SealedSecret | None = None`` (``null``/omitted means "keep the stored value", a
value means "rotate"). Empty strings are always rejected — clients must send ``null`` for keep.
"""


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

    Drives the form generator exactly like ``post_form`` does: each submitted page is validated
    (``form(**page)``) and the resulting model is sent back, so generators that access attributes of
    prior pages (the standard ``data.model_dump()`` pattern) advance correctly. A page's sealed field
    names are collected before attempting to advance past it; a page's own validation failure is the
    expected stopping point, and later pages' forms are then unknown.

    Args:
        form_generator: The workflow's input-form generator (or a single form class, or None).
        state: Current workflow state, passed to the generator as ``post_form`` would.
        user_inputs: Raw per-page input dicts, used to advance conditional generators.

    Returns:
        A ``(names, resolved)`` pair. ``resolved`` is True only when every submitted page's form class
        was positively identified (or there was nothing to submit); otherwise callers must omit values
        from logs rather than risk leaking cleartext. An empty-but-resolved result authoritatively
        means "no sealed fields".
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

    resolved = not pages
    try:
        for index in range(min(len(pages), _MAX_GENERATOR_PAGES)):
            names.update(_sealed_fields_of_model(yielded))
            if index + 1 >= len(pages):
                # Last submitted page identified; advancing past it is not needed for redaction.
                resolved = True
                break
            # Advance exactly like post_form: send the validated page model, never the raw dict.
            yielded = iterator.send(yielded(**pages[index]))
    except StopIteration:
        pass  # generator finished; any unsubmitted-later pages are unknown and keep resolved False
    except Exception:  # noqa: BLE001 - incomplete names omit values downstream
        logger.debug("Form generator walk ended early; sealed field names incomplete")
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

    When any submitted page's form class cannot be identified (unresolvable generator, or advancing
    would require passing a page whose validation failed), values are omitted entirely rather than
    risk leaking cleartext — the safe direction. Runs on the validation-error path only, never on the
    hot path.

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
