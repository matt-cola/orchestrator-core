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

"""Tests for sealed-secret rotation maintenance: pure census/rewrap logic and batch application."""

from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from orchestrator.core.forms.validators.sealed_secret import (
    SealedSecretDecryptionError,
    decrypt_sealed_secret,
    encrypt_sealed_secret,
    key_id_for_fernet_key,
)
from orchestrator.core.services import sealed_secrets as sealed_service
from orchestrator.core.services.sealed_secrets import (
    MALFORMED_KID,
    SEALED_SHREDDABLE,
    _kids_in_blob,
    _rewrap_batch,
    census_active_history,
    census_kids,
    current_kid,
    envelope_kid,
    rewrap_envelope,
)
from orchestrator.core.settings import app_settings
from orchestrator.core.workflow import ProcessStatus

KEY_A = Fernet.generate_key().decode()
KEY_B = Fernet.generate_key().decode()
KID_A = key_id_for_fernet_key(KEY_A)

PLAINTEXT = "rotation-test-secret"  # noqa: S105 - test fixture, not a credential


@pytest.fixture()
def single_key(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])


@pytest.fixture()
def rotated_ring(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B), SecretStr(KEY_A)])


@pytest.fixture()
def envelope_a(single_key):
    return encrypt_sealed_secret(PLAINTEXT)


def test_current_kid_reports_newest_key(single_key):
    assert current_kid() == KID_A


def test_current_kid_none_when_disabled(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [])
    assert current_kid() is None


def test_envelope_kid_parses_and_rejects():
    assert envelope_kid(f"fernet-v1:{KID_A}:QUJD") == KID_A
    assert envelope_kid("cleartext") is None
    assert envelope_kid("") is None
    assert envelope_kid(None) is None
    assert envelope_kid(123) is None


def test_census_kids_counts_per_kid():
    values = [f"fernet-v1:{KID_A}:QUJD", f"fernet-v1:{KID_A}:REVG", "fernet-v1:deadbeef:QUJD", "cleartext", ""]
    assert census_kids(values) == {KID_A: 2, "deadbeef": 1, MALFORMED_KID: 2}


def test_rewrap_envelope_upgrades_old_kid(rotated_ring, envelope_a):
    fresh = rewrap_envelope(envelope_a, key_id_for_fernet_key(KEY_B))
    assert fresh is not None
    assert fresh != envelope_a
    assert PLAINTEXT not in fresh
    assert decrypt_sealed_secret(fresh) == PLAINTEXT


def test_rewrap_envelope_skips_current_kid(single_key, envelope_a):
    assert rewrap_envelope(envelope_a, KID_A) is None


def test_rewrap_envelope_rejects_non_envelopes(single_key):
    with pytest.raises(SealedSecretDecryptionError):
        rewrap_envelope("cleartext", KID_A)


def test_rewrap_envelope_fails_on_unknown_key(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B)])
    foreign = Fernet.generate_key().decode()
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    # Envelope minted under a key that is not in the ring at all
    orphan = f"fernet-v1:{key_id_for_fernet_key(foreign)}:{Fernet(foreign.encode()).encrypt(b'x').decode()}"
    with pytest.raises(SealedSecretDecryptionError):
        rewrap_envelope(orphan, KID_A)


def _row(value):
    return SimpleNamespace(value=value, subscription_instance_value_id=uuid4())


def test_rewrap_batch_rewrites_old_and_skips_current(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    old_envelope = encrypt_sealed_secret(PLAINTEXT)
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B), SecretStr(KEY_A)])
    current = encrypt_sealed_secret("other")
    rows = [_row(old_envelope), _row(current)]
    rewrapped, already_current, failed = _rewrap_batch(rows, key_id_for_fernet_key(KEY_B))
    assert (rewrapped, already_current, failed) == (1, 1, [])
    assert decrypt_sealed_secret(rows[0].value) == PLAINTEXT
    assert rows[1].value == current


def test_rewrap_batch_collects_failures_without_values(rotated_ring):
    rows = [_row("cleartext-in-db"), _row("fernet-v1:deadbeef:QUJD")]
    rewrapped, already_current, failed = _rewrap_batch(rows, key_id_for_fernet_key(KEY_B))
    assert rewrapped == 0 and already_current == 0
    assert len(failed) == 2
    # Values untouched; failure records carry row ids only
    assert rows[0].value == "cleartext-in-db"
    assert all(PLAINTEXT not in row_id for row_id in failed)


# --- Active-history gate ---


def test_sealed_shreddable_is_completed_and_aborted_only():
    assert SEALED_SHREDDABLE == frozenset({ProcessStatus.COMPLETED, ProcessStatus.ABORTED})
    assert ProcessStatus.FAILED not in SEALED_SHREDDABLE
    assert ProcessStatus.INCONSISTENT_DATA not in SEALED_SHREDDABLE
    assert ProcessStatus.API_UNAVAILABLE not in SEALED_SHREDDABLE


def test_kids_in_blob_counts_envelopes_and_malformed(rotated_ring, envelope_a):
    current = encrypt_sealed_secret("other")
    blob = {"password": envelope_a, "nested": [{"token": current}, "plain"], "note": "cleartext"}
    kids = _kids_in_blob(blob)
    assert sorted(kids) == sorted([envelope_kid(envelope_a), envelope_kid(current)])
    assert _kids_in_blob({"v": "fernet-v1:truncated"}) == [MALFORMED_KID]
    assert _kids_in_blob({"v": "cleartext"}) == []
    assert _kids_in_blob(None) == []
    assert _kids_in_blob("fernet-v1:deadbeef:QUJD") == ["deadbeef"]


class _FakeScalars:
    def __init__(self, processes):
        self._processes = processes

    def all(self):
        # Mirror the SQL WHERE last_status NOT IN SHREDDABLE: terminal histories never reach Python.
        return [p for p in self._processes if p.last_status not in SEALED_SHREDDABLE]


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _FakeSession:
    """Serves the three queries census_active_history issues, in order.

    1. active processes  2. input_states blobs  3. process_steps blobs  4. step authors
    """

    def __init__(self, processes, input_rows, step_rows, author_rows=()):
        self._queues = [
            _FakeResult(processes),
            _FakeResult(input_rows),
            _FakeResult(step_rows),
            _FakeResult(author_rows),
        ]

    def scalars(self, query):
        del query
        return _FakeScalars(self._queues.pop(0).all())

    def execute(self, query):
        del query
        if not self._queues:
            raise AssertionError("unexpected extra query")
        return self._queues.pop(0)

    def get_bind(self):
        raise RuntimeError("no bind in unit tests")


def _process(pid, status, envelope_blob=None, created_by="alice", workflow_name="wf", started=None):
    del envelope_blob
    return SimpleNamespace(
        process_id=pid,
        last_status=status,
        created_by=created_by,
        assignee="NOC",
        started_at=started or datetime(2026, 1, 1, tzinfo=timezone.utc),
        workflow=SimpleNamespace(name=workflow_name),
    )


def _patch_session(monkeypatch, session):
    monkeypatch.setattr(sealed_service, "db", SimpleNamespace(session=session))


def test_census_active_history_counts_failed_and_running(monkeypatch):
    from orchestrator.core.services.sealed_secrets import current_kid as _current_kid

    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    envelope_a = encrypt_sealed_secret(PLAINTEXT)
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B), SecretStr(KEY_A)])
    target = _current_kid()
    assert target is not None
    running, failed, done, aborted = uuid4(), uuid4(), uuid4(), uuid4()
    processes = [
        _process(running, ProcessStatus.RUNNING),
        _process(failed, ProcessStatus.FAILED, created_by=None),
        _process(done, ProcessStatus.COMPLETED),
        _process(aborted, ProcessStatus.ABORTED),
    ]
    input_rows = [
        (running, {"password": envelope_a}),
        (failed, {"nested": [envelope_a]}),
        (done, {"password": envelope_a}),
        (aborted, {"password": envelope_a}),
    ]
    step_rows = [(failed, {"token": envelope_a})]
    author_rows = [(failed, "bob-step")]
    _patch_session(monkeypatch, _FakeSession(processes, input_rows, step_rows, author_rows))
    census, blocking = census_active_history()
    old_kid = envelope_kid(envelope_a)
    assert old_kid is not None and old_kid != target
    # Terminal histories are filtered before the walk: only running + failed (+1 step blob) count.
    assert census == {old_kid: 3}
    assert sorted(b.pid for b in blocking) == sorted([str(running), str(failed)])
    by_pid = {b.pid: b for b in blocking}
    assert by_pid[str(running)].started_by == "alice"
    assert by_pid[str(running)].workflow_name == "wf"
    assert by_pid[str(running)].last_status == str(ProcessStatus.RUNNING)
    # Nullable created_by falls back to the step author.
    assert by_pid[str(failed)].started_by == "bob-step"
    assert PLAINTEXT not in str(blocking)
    assert envelope_a not in str(blocking)


def test_census_active_history_ignores_current_only_and_cleartext(rotated_ring, monkeypatch):
    current = encrypt_sealed_secret("other")
    pid = uuid4()
    processes = [_process(pid, ProcessStatus.SUSPENDED)]
    _patch_session(monkeypatch, _FakeSession(processes, [(pid, {"password": current, "note": "hi"})], []))
    census, blocking = census_active_history()
    assert census == {envelope_kid(current): 1}
    assert blocking == []


def test_census_active_history_malformed_blocks_with_cleanup_note(rotated_ring, monkeypatch):
    pid = uuid4()
    processes = [_process(pid, ProcessStatus.WAITING)]
    _patch_session(monkeypatch, _FakeSession(processes, [(pid, {"v": "fernet-v1:truncated"})], []))
    census, blocking = census_active_history()
    assert census == {MALFORMED_KID: 1}
    assert [b.pid for b in blocking] == [str(pid)]


def test_census_active_history_started_by_falls_back_to_assignee(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    envelope_a = encrypt_sealed_secret(PLAINTEXT)
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B), SecretStr(KEY_A)])
    pid = uuid4()
    proc = _process(pid, ProcessStatus.RUNNING, created_by=None)
    proc.assignee = "NOC-fallback"
    _patch_session(monkeypatch, _FakeSession([proc], [(pid, {"password": envelope_a})], []))
    _, blocking = census_active_history()
    assert blocking[0].started_by == "NOC-fallback"
