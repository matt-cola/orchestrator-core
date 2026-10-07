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

"""Active-history gate against a real Postgres.

The JSONB prefilter and the NOT IN status filter must actually execute.

The unit tests fake the session, so they cannot catch bad SQL, a wrong jsonpath expression or a
jsonb/jsonpath type mismatch - all of which broke this on the way in.
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from orchestrator.core.db import InputStateTable, ProcessStepTable, ProcessTable, WorkflowTable, db
from orchestrator.core.forms.validators.sealed_secret import encrypt_sealed_secret, key_id_for_fernet_key
from orchestrator.core.services.sealed_secrets import (
    MALFORMED_KID,
    BlockingProcess,
    census_active_history,
    current_kid,
)
from orchestrator.core.settings import app_settings
from orchestrator.core.workflow import ProcessStatus

pytestmark = pytest.mark.usefixtures("database")

KEY_OLD = "hc9nX0kFYyYAP-XO8vV3m3vbfPZFv2XKt0d6vLQpFGs="  # noqa: S105 - test key, not a credential
KID_OLD = key_id_for_fernet_key(KEY_OLD)
# Envelope-shaped but not decryptable: the gate counts by key id, it never decrypts.
OLD_ENVELOPE = f"fernet-v1:{KID_OLD}:ZHVtbXktZW52ZWxvcGUtbm90LWEtcmVhbC1rZXk="


@pytest.fixture()
def new_key() -> str:
    """A fresh key that is *not* the one OLD_ENVELOPE was sealed under."""
    return Fernet.generate_key().decode()


@pytest.fixture()
def rotated_ring(monkeypatch, new_key: str) -> None:
    """Ring with the new key first, so every OLD_ENVELOPE sits on a non-current key."""
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(new_key), SecretStr(KEY_OLD)])


@pytest.fixture()
def workflow_row():
    """A real workflow row: processes.workflow_id is a foreign key, so the gate test needs one."""
    workflow_id = uuid4()
    db.session.add(
        WorkflowTable(
            workflow_id=workflow_id,
            name=f"gate-test-{workflow_id}",
            target="RECONCILE",
            description="sealed-secret gate test",
            is_task=False,
        )
    )
    db.session.commit()
    # No teardown needed: the autouse db_session fixture wraps each test in a transaction that is
    # rolled back, so seeded rows never reach the next test. An explicit rollback here would instead
    # discard this test's own workflow row mid-test.
    return workflow_id


def _process(workflow_id: UUID, status: str, created_by: str | None = "alice") -> ProcessTable:
    process = ProcessTable(
        process_id=uuid4(),
        workflow_id=workflow_id,
        last_status=status,
        created_by=created_by,
        is_task=False,
    )
    db.session.add(process)
    return process


def _add_input(process_id: UUID, state: dict) -> None:
    db.session.add(InputStateTable(process_id=process_id, input_state=state, input_type="user_input"))


def _add_step(process_id: UUID, state: dict) -> None:
    db.session.add(ProcessStepTable(process_id=process_id, name="step", status="complete", state=state))


def _drop_processes(pids: list[UUID]) -> None:
    """Delete exactly the given processes and their history, inside the test's transaction."""
    for model in (ProcessStepTable, InputStateTable, ProcessTable):
        db.session.query(model).filter(model.process_id.in_(pids)).delete(synchronize_session=False)
    db.session.commit()


@pytest.fixture()
def seeded(rotated_ring, workflow_row: UUID):
    """One active process with an old-kid envelope in input history, one in step state, one terminated."""
    terminated = _process(workflow_row, ProcessStatus.COMPLETED)
    _add_input(terminated.process_id, {"password": OLD_ENVELOPE})
    failed = _process(workflow_row, ProcessStatus.FAILED, created_by=None)
    _add_input(failed.process_id, {"nested": [{"password": OLD_ENVELOPE}]})
    running = _process(workflow_row, ProcessStatus.RUNNING)
    _add_step(running.process_id, {"token": OLD_ENVELOPE})
    db.session.commit()
    return {
        "workflow_id": workflow_row,
        "failed": failed.process_id,
        "running": running.process_id,
        "terminated": terminated.process_id,
    }


def test_census_active_history_sql_counts_only_active(seeded):
    census, blocking = census_active_history()

    assert {record.pid for record in blocking} == {str(seeded["failed"]), str(seeded["running"])}
    assert census.get(KID_OLD) == 2
    assert str(seeded["terminated"]) not in {record.pid for record in blocking}
    assert OLD_ENVELOPE not in str(blocking)


def test_census_active_history_is_clean_when_all_current(seeded):
    _drop_processes([seeded["failed"], seeded["running"], seeded["terminated"]])
    process = _process(seeded["workflow_id"], ProcessStatus.RUNNING)
    _add_input(process.process_id, {"password": encrypt_sealed_secret("value")})
    db.session.commit()

    census, blocking = census_active_history()

    assert blocking == []
    assert current_kid() in census


def test_census_active_history_prefilter_finds_nested_envelope(seeded):
    """The jsonpath prefilter must not miss envelopes nested inside arrays/objects."""
    process = _process(seeded["workflow_id"], ProcessStatus.WAITING)
    db.session.add(
        InputStateTable(
            process_id=process.process_id,
            input_state={"a": [{"b": {"c": [OLD_ENVELOPE]}}]},
            input_type="user_input",
        )
    )
    db.session.commit()

    _, blocking = census_active_history()

    assert str(process.process_id) in {record.pid for record in blocking}


def test_census_active_history_malformed_blocks(seeded):
    """A truncated envelope must reach the walk and block, not be silently skipped."""
    process = _process(seeded["workflow_id"], ProcessStatus.SUSPENDED)
    _add_input(process.process_id, {"v": "fernet-v1:truncated"})
    db.session.commit()

    census, blocking = census_active_history()

    assert census.get(MALFORMED_KID) == 1
    assert str(process.process_id) in {record.pid for record in blocking}


def test_census_active_history_with_no_processes(rotated_ring):
    census, blocking = census_active_history()

    assert isinstance(census, dict)
    assert isinstance(blocking, list)
    assert all(isinstance(record, BlockingProcess) for record in blocking)


def test_current_kid_matches_first_ring_entry(rotated_ring, new_key: str):
    assert current_kid() == key_id_for_fernet_key(new_key)


def test_blocking_report_never_contains_values_and_is_utc(seeded):
    _, blocking = census_active_history()

    assert blocking
    for record in blocking:
        assert OLD_ENVELOPE not in str(record)
        assert record.started_at is not None
        assert datetime.fromisoformat(record.started_at).tzinfo is timezone.utc


def test_blocking_report_resolves_workflow_name_and_owner(seeded):
    _, blocking = census_active_history()
    by_pid = {record.pid: record for record in blocking}

    running = by_pid[str(seeded["running"])]
    assert running.workflow_name is not None
    assert running.started_by == "alice"
    assert running.last_status == str(ProcessStatus.RUNNING)
    # created_by is NULL on the failed process: the report still names an owner for the SOP.
    assert by_pid[str(seeded["failed"])].started_by
