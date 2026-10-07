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

"""Tests for the `secrets rewrap-sealed-secrets` CLI: flags, exit codes and output. DB is mocked."""

from typer.testing import CliRunner

from orchestrator.core.cli.secrets import app
from orchestrator.core.services.sealed_secrets import BlockingProcess, RewrapReport

runner = CliRunner()

KID_NEW = "aaaa1111"
KID_OLD = "bbbb2222"


def _patch_target(monkeypatch, kid=KID_NEW):
    monkeypatch.setattr("orchestrator.core.cli.secrets.current_kid", lambda: kid)


def _patch_empty_history(monkeypatch):
    monkeypatch.setattr("orchestrator.core.cli.secrets.census_active_history", lambda **kwargs: ({}, []))


def _report(**overrides):
    base = {
        "scanned": 3,
        "rewrapped": 2,
        "already_current": 1,
        "failed_row_ids": (),
        "kids_before": {KID_NEW: 1, KID_OLD: 2},
        "kids_after": {KID_NEW: 3},
        "dry_run": True,
    }
    return RewrapReport(**(base | overrides))


def test_check_clean_exits_zero(monkeypatch):
    _patch_target(monkeypatch)
    _patch_empty_history(monkeypatch)
    monkeypatch.setattr("orchestrator.core.cli.secrets.census_current_values", lambda: {KID_NEW: 5})
    result = runner.invoke(app, ["--check"])
    assert result.exit_code == 0, result.output
    assert KID_NEW in result.output


def test_check_dirty_exits_one(monkeypatch):
    _patch_target(monkeypatch)
    _patch_empty_history(monkeypatch)
    monkeypatch.setattr("orchestrator.core.cli.secrets.census_current_values", lambda: {KID_NEW: 1, KID_OLD: 2})
    result = runner.invoke(app, ["--check"])
    assert result.exit_code == 1, result.output
    assert KID_OLD in result.output


def test_check_empty_store_exits_zero(monkeypatch):
    _patch_target(monkeypatch)
    _patch_empty_history(monkeypatch)
    monkeypatch.setattr("orchestrator.core.cli.secrets.census_current_values", lambda: {})
    result = runner.invoke(app, ["--check"])
    assert result.exit_code == 0, result.output


def test_check_history_dirty_exits_one_and_renders_blocking(monkeypatch):
    _patch_target(monkeypatch)
    monkeypatch.setattr("orchestrator.core.cli.secrets.census_current_values", lambda: {KID_NEW: 5})
    blocking = [
        BlockingProcess(
            pid="pid-1", workflow_name="wf", last_status="failed", started_at="2026-01-01", started_by="alice"
        )
    ]
    monkeypatch.setattr(
        "orchestrator.core.cli.secrets.census_active_history", lambda **kwargs: ({KID_OLD: 2}, blocking)
    )
    result = runner.invoke(app, ["--check"])
    assert result.exit_code == 1, result.output
    assert "Blocked" in result.output
    assert "pid-1" in result.output
    assert "alice" in result.output
    assert "PUT /resume" in result.output
    assert "PUT /abort" in result.output
    assert KID_OLD in result.output


def test_check_history_current_only_exits_zero(monkeypatch):
    _patch_target(monkeypatch)
    monkeypatch.setattr("orchestrator.core.cli.secrets.census_current_values", lambda: {KID_NEW: 5})
    monkeypatch.setattr("orchestrator.core.cli.secrets.census_active_history", lambda **kwargs: ({KID_NEW: 3}, []))
    result = runner.invoke(app, ["--check"])
    assert result.exit_code == 0, result.output


def test_disabled_exits_two(monkeypatch):
    monkeypatch.setattr("orchestrator.core.cli.secrets.current_kid", lambda: None)
    result = runner.invoke(app, ["--check"])
    assert result.exit_code == 2, result.output


def test_default_is_dry_run(monkeypatch):
    _patch_target(monkeypatch)
    calls = []
    monkeypatch.setattr(
        "orchestrator.core.cli.secrets.rewrap_current_values",
        lambda **kwargs: calls.append(kwargs) or _report(),
    )
    result = runner.invoke(app, [])
    assert result.exit_code == 0, result.output
    assert calls == [{"batch_size": 500, "dry_run": True}]
    assert "Dry run" in result.output
    assert "--execute" in result.output


def test_execute_runs_and_reports(monkeypatch):
    _patch_target(monkeypatch)
    _patch_empty_history(monkeypatch)
    calls = []

    def fake_rewrap(**kwargs):
        calls.append(kwargs)
        report = _report()
        if kwargs.get("dry_run"):
            return report
        return RewrapReport(
            scanned=3,
            rewrapped=2,
            already_current=1,
            failed_row_ids=(),
            kids_before={KID_NEW: 1, KID_OLD: 2},
            kids_after={KID_NEW: 3},
            dry_run=False,
        )

    monkeypatch.setattr("orchestrator.core.cli.secrets.rewrap_current_values", fake_rewrap)
    result = runner.invoke(app, ["--execute", "--yes"])
    assert result.exit_code == 0, result.output
    assert {"batch_size": 500, "dry_run": True} in calls
    assert {"batch_size": 500, "dry_run": False} in calls
    assert "Executed" in result.output


def test_execute_aborted_on_decline(monkeypatch):
    _patch_target(monkeypatch)
    _patch_empty_history(monkeypatch)
    calls = []
    monkeypatch.setattr(
        "orchestrator.core.cli.secrets.rewrap_current_values",
        lambda **kwargs: calls.append(kwargs) or _report(),
    )
    result = runner.invoke(app, ["--execute"], input="n\n")
    assert result.exit_code != 0
    assert calls == [{"batch_size": 500, "dry_run": True}]


def test_execute_with_failures_exits_one(monkeypatch):
    _patch_target(monkeypatch)
    _patch_empty_history(monkeypatch)

    def fake_rewrap(**kwargs):
        if kwargs.get("dry_run"):
            return _report()
        return _report(dry_run=False, rewrapped=1, failed_row_ids=("row-1",))

    monkeypatch.setattr("orchestrator.core.cli.secrets.rewrap_current_values", fake_rewrap)
    result = runner.invoke(app, ["--execute", "--yes"])
    assert result.exit_code == 1, result.output
    assert "row-1" in result.output


def test_execute_aborts_when_history_blocks(monkeypatch):
    _patch_target(monkeypatch)
    blocking = [
        BlockingProcess(
            pid="pid-9", workflow_name="wf", last_status="failed", started_at="2026-01-02", started_by="bob"
        )
    ]
    monkeypatch.setattr(
        "orchestrator.core.cli.secrets.census_active_history", lambda **kwargs: ({KID_OLD: 1}, blocking)
    )
    calls = []
    monkeypatch.setattr(
        "orchestrator.core.cli.secrets.rewrap_current_values",
        lambda **kwargs: calls.append(kwargs) or _report(),
    )
    result = runner.invoke(app, ["--execute", "--yes"])
    assert result.exit_code != 0, result.output
    assert calls == []
    assert "Blocked" in result.output
    assert "pid-9" in result.output
    assert "bob" in result.output
    assert "never aborts" in result.output


def test_nothing_to_do(monkeypatch):
    _patch_target(monkeypatch)
    _patch_empty_history(monkeypatch)
    empty = RewrapReport(
        scanned=0, rewrapped=0, already_current=0, failed_row_ids=(), kids_before={}, kids_after={}, dry_run=True
    )
    monkeypatch.setattr("orchestrator.core.cli.secrets.rewrap_current_values", lambda **kwargs: empty)
    result = runner.invoke(app, ["--execute", "--yes"])
    assert result.exit_code == 0, result.output
    assert "nothing to do" in result.output


def test_report_never_contains_secret_values(monkeypatch):
    _patch_target(monkeypatch)
    monkeypatch.setattr("orchestrator.core.cli.secrets.rewrap_current_values", lambda **kwargs: _report())
    result = runner.invoke(app, [])
    assert "rotation-test-secret" not in result.output
    assert "s3cr3t" not in result.output
