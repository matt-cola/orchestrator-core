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

"""Rotation maintenance for sealed-secret envelopes.

Key rotation itself is lazy: prepending a new key to ``SEALED_SECRETS_FERNET_KEYS`` makes new writes
use it while old envelopes keep decrypting through the ring. This module offers the optional,
manually-invoked hygiene step: re-encrypting **current subscription values** to the newest key so the
old key can be destroyed sooner.

Deliberately out of scope: ``input_states`` and ``process_steps`` history is never rewritten (audit
trail). The old key therefore remains required for history until it ages out, whatever this command
does — see the sealed-secrets runbook.
"""

from collections import Counter
from collections.abc import Generator, Iterable
from dataclasses import dataclass, field
from uuid import UUID

import structlog
from sqlalchemy import select

from orchestrator.core.db import db
from orchestrator.core.db.database import transactional
from orchestrator.core.db.models import SubscriptionInstanceValueTable
from orchestrator.core.forms.validators.sealed_secret import (
    SealedSecretDecryptionError,
    decrypt_sealed_secret,
    encrypt_sealed_secret,
    is_sealed_envelope,
    key_id_for_fernet_key,
)

logger = structlog.get_logger(__name__)

ENVELOPE_ROW_FILTER = "fernet-v1:%"
"""SQL LIKE filter matching sealed-envelope resource values. Envelopes always carry this prefix."""

MALFORMED_KID = "malformed"
"""Census bucket for envelope-looking values whose key id cannot be parsed."""


@dataclass(frozen=True)
class RewrapReport:
    """Outcome of a rewrap run. Row ids only — never secret values."""

    scanned: int = 0
    rewrapped: int = 0
    already_current: int = 0
    failed_row_ids: tuple[str, ...] = ()
    kids_before: dict[str, int] = field(default_factory=dict)
    kids_after: dict[str, int] = field(default_factory=dict)
    dry_run: bool = True


def current_kid() -> str | None:
    """Return the key id new envelopes are minted with, or None when sealed secrets are disabled."""
    from orchestrator.core.settings import app_settings

    keys = app_settings.SEALED_SECRETS_FERNET_KEYS
    if not keys:
        return None
    return key_id_for_fernet_key(keys[0].get_secret_value())


def envelope_kid(value: str) -> str | None:
    """Parse the key id out of an envelope, or None when the value is not a well-formed envelope."""
    if not is_sealed_envelope(value):
        return None
    try:
        _, kid, _ = value.split(":", 2)
    except ValueError:
        return MALFORMED_KID
    return kid or MALFORMED_KID


def census_kids(values: Iterable[str]) -> dict[str, int]:
    """Count values per envelope key id. Pure; the unit-testable core of ``--check``."""
    counts: Counter[str] = Counter()
    for value in values:
        counts[envelope_kid(value) or MALFORMED_KID] += 1
    return dict(counts)


def rewrap_envelope(value: str, target_kid: str) -> str | None:
    """Re-encrypt one envelope to the newest key.

    Args:
        value: The stored envelope.
        target_kid: Key id new envelopes must carry (the ring's newest key).

    Returns:
        The re-encrypted envelope, or None when the value already carries ``target_kid``.

    Raises:
        SealedSecretDecryptionError: When the value is not an envelope or decrypts with no key.
            Callers record the row id and continue; the value itself never leaves this function.
    """
    kid = envelope_kid(value)
    if kid is None:
        raise SealedSecretDecryptionError("Not a sealed envelope")
    if kid == target_kid:
        return None
    plaintext = decrypt_sealed_secret(value)
    fresh = encrypt_sealed_secret(plaintext)
    if decrypt_sealed_secret(fresh) != plaintext:
        raise SealedSecretDecryptionError("Rewrap round-trip verification failed")
    return fresh


def census_current_values() -> dict[str, int]:
    """Count stored sealed envelopes per key id across all current subscription values.

    Returns:
        Mapping of key id (or ``"malformed"``) to row count. Empty when no sealed values exist.
    """
    rows = db.session.scalars(
        select(SubscriptionInstanceValueTable.value).where(
            SubscriptionInstanceValueTable.value.like(ENVELOPE_ROW_FILTER)
        )
    ).all()
    return census_kids(rows)


def _rewrap_batch(rows: list[SubscriptionInstanceValueTable], target_kid: str) -> tuple[int, int, list[str]]:
    """Re-encrypt one batch in place. Returns (rewrapped, already_current, failed_row_ids)."""
    rewrapped, already_current, failed = 0, 0, []
    for row in rows:
        try:
            fresh = rewrap_envelope(row.value, target_kid)
        except SealedSecretDecryptionError:
            logger.warning("Skipping undecryptable sealed value", row_id=str(row.subscription_instance_value_id))
            failed.append(str(row.subscription_instance_value_id))
            continue
        if fresh is None:
            already_current += 1
        else:
            row.value = fresh
            rewrapped += 1
    return rewrapped, already_current, failed


def _iter_envelope_batches(batch_size: int) -> Generator[list[SubscriptionInstanceValueTable], None, None]:
    """Yield sealed-envelope rows in keyset-ordered batches. Stops at the first short batch."""
    last_id: UUID | None = None
    while True:
        query = (
            select(SubscriptionInstanceValueTable)
            .where(SubscriptionInstanceValueTable.value.like(ENVELOPE_ROW_FILTER))
            .order_by(SubscriptionInstanceValueTable.subscription_instance_value_id)
            .limit(batch_size)
        )
        if last_id is not None:
            query = query.where(SubscriptionInstanceValueTable.subscription_instance_value_id > last_id)
        rows = list(db.session.scalars(query).all())
        if not rows:
            return
        last_id = rows[-1].subscription_instance_value_id
        yield rows


def _preview_rewrap(target_kid: str, batch_size: int, kids_before: dict[str, int]) -> RewrapReport:
    """Scan without writing; project the post-rewrap census from per-kid move counts."""
    scanned, rewrapped, already_current = 0, 0, 0
    failed: list[str] = []
    moves: Counter[str] = Counter()
    for rows in _iter_envelope_batches(batch_size):
        scanned += len(rows)
        for row in rows:
            kid = envelope_kid(row.value)
            if kid == target_kid:
                already_current += 1
            elif kid is None:
                failed.append(str(row.subscription_instance_value_id))
            else:
                moves[kid] += 1
                rewrapped += 1
    kids_after = dict(kids_before)
    for kid, count in moves.items():
        kids_after[kid] = kids_after.get(kid, 0) - count
        if kids_after[kid] <= 0:
            del kids_after[kid]
    kids_after[target_kid] = kids_after.get(target_kid, 0) + rewrapped
    return RewrapReport(
        scanned=scanned,
        rewrapped=rewrapped,
        already_current=already_current,
        failed_row_ids=tuple(failed),
        kids_before=kids_before,
        kids_after=kids_after,
        dry_run=True,
    )


def _execute_rewrap(target_kid: str, batch_size: int, kids_before: dict[str, int]) -> RewrapReport:
    """Rewrite old-kid envelopes batch by batch, committing each batch so reruns resume."""
    scanned, rewrapped, already_current = 0, 0, 0
    failed: list[str] = []
    for rows in _iter_envelope_batches(batch_size):
        scanned += len(rows)
        with transactional(db, logger):
            batch_rewrapped, batch_current, batch_failed = _rewrap_batch(rows, target_kid)
        rewrapped += batch_rewrapped
        already_current += batch_current
        failed.extend(batch_failed)
        logger.info(
            "Rewrapped sealed values batch",
            batch_size=len(rows),
            rewrapped_total=rewrapped,
            scanned_total=scanned,
        )
    return RewrapReport(
        scanned=scanned,
        rewrapped=rewrapped,
        already_current=already_current,
        failed_row_ids=tuple(failed),
        kids_before=kids_before,
        kids_after=census_current_values(),
        dry_run=False,
    )


def rewrap_current_values(*, batch_size: int = 500, dry_run: bool = True) -> RewrapReport:
    """Re-encrypt current subscription values carrying old-kid envelopes to the newest key.

    Idempotent and resumable: a crash leaves earlier batches committed (per-batch transactions) and a
    rerun continues where it stopped. History tables are untouched by design.

    Args:
        batch_size: Rows per transaction. Small batches bound lock time; large batches run faster.
        dry_run: When True, scan and report without writing anything.

    Returns:
        A :class:`RewrapReport` with before/after key-id census (projected for dry runs).

    Raises:
        SealedSecretDecryptionError: When sealed secrets are disabled (fail closed: without keys there
            is nothing safe to rewrite to).
    """
    target = current_kid()
    if target is None:
        raise SealedSecretDecryptionError("Sealed secrets are disabled; nothing to rewrap to")
    kids_before = census_current_values()
    if dry_run:
        return _preview_rewrap(target, batch_size, kids_before)
    return _execute_rewrap(target, batch_size, kids_before)
