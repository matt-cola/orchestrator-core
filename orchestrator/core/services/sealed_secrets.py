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

Draining is a prerequisite, not a side effect: :func:`census_active_history` reports which active
processes still hold old-kid envelopes so an operator can retry or abort them, and the CLI refuses to
run while any are left. The tool never aborts a process itself. Every run is audit-logged with kid
counts and row/pid totals only — never values. Escrow the old key material until ``--check`` is green
immediately before the drop; after the drop, terminated history shreds (rows remain, secrets do not).
"""

from collections import Counter
from collections.abc import Generator, Iterable
from dataclasses import dataclass, field
from itertools import chain
from typing import Any
from uuid import UUID

import structlog
from sqlalchemy import cast, func, select
from sqlalchemy.dialects.postgresql import JSONPATH
from sqlalchemy.orm import selectinload

from orchestrator.core.db import InputStateTable, ProcessStepTable, ProcessTable, db
from orchestrator.core.db.database import transactional
from orchestrator.core.db.models import SubscriptionInstanceValueTable
from orchestrator.core.forms.validators.sealed_secret import (
    SealedSecretDecryptionError,
    decrypt_sealed_secret,
    encrypt_sealed_secret,
    is_sealed_envelope,
    key_id_for_fernet_key,
)
from orchestrator.core.services.processes import SYSTEM_USER
from orchestrator.core.workflow import ProcessStatus

logger = structlog.get_logger(__name__)

ENVELOPE_ROW_FILTER = "fernet-v1:%"
"""SQL LIKE filter matching sealed-envelope resource values. Envelopes always carry this prefix."""

MALFORMED_KID = "malformed"
"""Census bucket for envelope-looking values whose key id cannot be parsed."""

ENVELOPE_JSONPATH = '$.** ? (@.type() == "string" && @ starts with "fernet-v1:")'
"""jsonpath predicate matching any string leaf that starts with the sealed-envelope prefix.

``$.**`` is the recursive wildcard (the jsonpath ``..`` descendant operator does not exist, and
``strict $..*`` is a syntax error). The prefix match — rather than the full envelope regex — keeps
truncated envelopes in the result set so the Python walk can count them as ``malformed`` instead of
the prefilter silently dropping them.
"""

SEALED_SHREDDABLE = frozenset({ProcessStatus.COMPLETED, ProcessStatus.ABORTED})
"""History states whose sealed envelopes no longer block old-key destruction.

Only ``completed``/``aborted`` histories may shred (audit keeps the row, the secret becomes
unreadable — accepted). ``failed`` (including the retryable ``inconsistent_data`` /
``api_unavailable`` subtypes, which resume via ``resume``/``PUT /resume``) and every other live
state stay active. Deliberately separate from ``websocket._TERMINAL_PROCESS_STATUSES`` (which
includes FAILED for cache invalidation): different question, different set.
"""


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


@dataclass(frozen=True)
class BlockingProcess:
    """An active process whose history still carries non-current sealed envelopes. Ids only."""

    pid: str
    workflow_name: str | None
    last_status: str
    started_at: str | None
    started_by: str


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


def _iter_string_leaves(value: Any) -> Generator[str, None, None]:
    """Yield every string leaf under a JSON blob (dict/list/tuple/set/str). Pure."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _iter_string_leaves(item)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_string_leaves(item)


def _kids_in_blob(blob: Any) -> list[str]:
    """Collect envelope key ids from one JSON history blob. Pure; never returns values.

    Strings starting with the envelope prefix but failing the envelope regex count as
    ``malformed``: a truncated/corrupt envelope that needs manual cleanup before the old key
    goes, so it must block key destruction like any other non-current envelope.
    """
    kids = []
    for leaf in _iter_string_leaves(blob):
        if not leaf.startswith("fernet-v1:"):
            continue
        kids.append(envelope_kid(leaf) or MALFORMED_KID)
    return kids


def _postgres_envelope_prefilter(column: Any) -> Any | None:
    """Return a Postgres ``jsonb_path_exists`` prefilter for a JSONB column, else None.

    Applied on Postgres only (checked via the session bind dialect); other backends (e.g. sqlite
    in tests) skip the prefilter and rely on the Python leaf walk, which is always correct. A
    future GIN index on the history JSONB columns would make this prefilter indexed; no index on
    resource ``value`` exists today, which is why ``cast(Text).like`` is explicitly avoided here
    (seq-scan with wrong escaping semantics for JSON).
    """
    try:
        bind = db.session.get_bind()
        dialect = getattr(bind, "dialect", None)
        if getattr(dialect, "name", None) != "postgresql":
            return None
    except Exception:  # noqa: BLE001 - no bind (unit tests with mocked session); walk in Python
        return None
    # The path argument must be jsonpath, not jsonb/varchar: jsonb_path_exists(jsonb, jsonpath)
    # is the only signature Postgres provides, and an uncast Python str binds as varchar.
    return func.jsonb_path_exists(column, cast(ENVELOPE_JSONPATH, JSONPATH))


def _resolve_started_by(process: ProcessTable, step_created_by: str | None) -> str:
    """Resolve a process owner for the blocking report: creator, else step author, else assignee."""
    return process.created_by or step_created_by or process.assignee or SYSTEM_USER


def _blocking_record(process: ProcessTable, step_created_by: str | None) -> BlockingProcess:
    """Build the owner-actionable report row for one blocking process. Ids and metadata only."""
    return BlockingProcess(
        pid=str(process.process_id),
        workflow_name=process.workflow.name if process.workflow else None,
        last_status=str(process.last_status),
        started_at=process.started_at.isoformat() if process.started_at else None,
        started_by=_resolve_started_by(process, step_created_by),
    )


def _step_authors(pids: list[UUID]) -> dict[Any, str]:
    """First non-null ``process_steps.created_by`` per pid, for owner resolution.

    Deliberately unfiltered: the envelope prefilter would hide steps that hold no envelope, and the
    owner fallback must not depend on whether a step happened to carry a secret.
    """
    if not pids:
        return {}
    rows = db.session.execute(
        select(ProcessStepTable.process_id, ProcessStepTable.created_by)
        .where(ProcessStepTable.process_id.in_(pids))
        .order_by(ProcessStepTable.process_id, ProcessStepTable.started_at)
    ).all()
    authors: dict[Any, str] = {}
    for pid, author in rows:
        if author and pid not in authors:
            authors[pid] = author
    return authors


def _history_kids_by_pid(pids: list[UUID]) -> dict[Any, list[str]]:
    """Collect envelope kids per pid across both history tables.

    Args:
        pids: Process ids of the active processes to inspect.

    Returns:
        ``kids_by_pid``, seeded for every requested pid so the caller never has to distinguish
        "no history" from "history without envelopes".
    """
    input_query = select(InputStateTable.process_id, InputStateTable.input_state).where(
        InputStateTable.process_id.in_(pids)
    )
    step_query = select(ProcessStepTable.process_id, ProcessStepTable.state).where(
        ProcessStepTable.process_id.in_(pids)
    )
    if (prefilter := _postgres_envelope_prefilter(InputStateTable.input_state)) is not None:
        input_query = input_query.where(prefilter)
    if (prefilter := _postgres_envelope_prefilter(ProcessStepTable.state)) is not None:
        step_query = step_query.where(prefilter)

    kids_by_pid: dict[Any, list[str]] = {pid: [] for pid in pids}
    for query in (input_query, step_query):
        for row_pid, blob in db.session.execute(query).all():
            if row_pid in kids_by_pid:
                kids_by_pid[row_pid].extend(_kids_in_blob(blob))
    return kids_by_pid


def census_active_history(*, target_kid: str | None = None) -> tuple[dict[str, int], list[BlockingProcess]]:
    """Count sealed envelopes per key id across **active** process history.

    Active means ``ProcessTable.last_status NOT IN SEALED_SHREDDABLE``: running, suspended,
    waiting, failed (including the retryable ``inconsistent_data``/``api_unavailable`` subtypes)
    and any other non-terminal state. Completed/aborted histories are ignored — their envelopes
    may shred (audit keeps the row, the secret becomes unreadable).

    Both ``InputStateTable.input_state`` and ``ProcessStepTable.state`` JSONB blobs are walked
    (Postgres prefilters via ``jsonb_path_exists`` when available; the Python leaf walk is always
    authoritative). Only counts and process ids are returned — never secret values.

    Note: ``kid`` attribution is a hint, not proof — kids are 8-hex sha256 prefixes and could
    theoretically collide, while :func:`decrypt_sealed_secret` tries all keys kid-first. The
    blocking list is therefore conservative: any non-current (or malformed) envelope blocks.

    Args:
        target_kid: Key id new envelopes must carry. Defaults to :func:`current_kid`; when None
            (sealed secrets disabled) every envelope counts as blocking.

    Returns:
        A ``(census, blocking)`` pair: per-kid envelope counts across active history, and the
        blocking processes (those holding at least one non-current/malformed envelope) with
        owner info for the drain SOP.
    """
    target = target_kid if target_kid is not None else current_kid()
    active = list(
        db.session.scalars(
            select(ProcessTable)
            .options(selectinload(ProcessTable.workflow))
            .where(ProcessTable.last_status.not_in(SEALED_SHREDDABLE))
        ).all()
    )
    if not active:
        return {}, []

    pids = [process.process_id for process in active]
    kids_by_pid = _history_kids_by_pid(pids)
    census: Counter[str] = Counter(chain.from_iterable(kids_by_pid.values()))

    def is_blocking(kids: list[str]) -> bool:
        return any(kid == MALFORMED_KID or kid != target for kid in kids)

    blocking_processes = [process for process in active if is_blocking(kids_by_pid.get(process.process_id, []))]
    step_authors = _step_authors([process.process_id for process in blocking_processes])
    blocking = sorted(
        (_blocking_record(process, step_authors.get(process.process_id)) for process in blocking_processes),
        key=lambda record: record.pid,
    )
    return dict(census), blocking


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
    """Yield sealed-envelope rows in keyset-ordered batches. Stops at the first empty fetch."""
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
            elif kid is None or kid == MALFORMED_KID:
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
    report = (
        _preview_rewrap(target, batch_size, kids_before)
        if dry_run
        else _execute_rewrap(target, batch_size, kids_before)
    )
    # Audit trail for the manual rotation: kid census and totals only, never values.
    logger.info(
        "Sealed secret rewrap finished" if not dry_run else "Sealed secret rewrap dry run finished",
        target_kid=target,
        dry_run=dry_run,
        scanned=report.scanned,
        rewrapped=report.rewrapped,
        already_current=report.already_current,
        failed_rows=len(report.failed_row_ids),
        kids_before=report.kids_before,
        kids_after=report.kids_after,
    )
    return report
