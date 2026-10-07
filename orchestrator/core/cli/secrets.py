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

import typer
from structlog import get_logger

from orchestrator.core.db import init_database
from orchestrator.core.services.sealed_secrets import (
    BlockingProcess,
    RewrapReport,
    census_active_history,
    census_current_values,
    current_kid,
    rewrap_current_values,
)
from orchestrator.core.settings import app_settings

logger = get_logger(__name__)

app: typer.Typer = typer.Typer()


def _render_census(census: dict[str, int], target_kid: str | None) -> str:
    """Render a kid census as stable, human-readable lines without ever touching secret values."""
    if not census:
        return "  (no sealed values stored)"
    lines = []
    for kid in sorted(census):
        marker = "  <-- current" if kid == target_kid else ""
        lines.append(f"  {kid}: {census[kid]} row(s){marker}")
    return "\n".join(lines)


def _render_blocking_processes(blocking: list[BlockingProcess]) -> str:
    """Render active-history blockers as owner-actionable rows. Ids and counts only, never values."""
    lines = [
        f"Blocked: {len(blocking)} active process(es) (incl. failed) still carry old-kid envelopes in history.",
        "Drain first: retry to COMPLETED (PUT /resume) or ask the starter to abort (PUT /abort) — "
        "this tool never aborts processes.",
        "pid|workflow|status|started|started_by",
    ]
    lines.extend(
        f"  {record.pid}|{record.workflow_name}|{record.last_status}|{record.started_at}|{record.started_by}"
        for record in blocking
    )
    return "\n".join(lines)


def _render_report(report: RewrapReport) -> str:
    """Render a rewrap report for terminal output."""
    heading = "Dry run (no writes)" if report.dry_run else "Executed"
    lines = [
        f"{heading}: scanned={report.scanned} rewrapped={report.rewrapped} "
        f"already_current={report.already_current} failed={len(report.failed_row_ids)}",
        "Before:",
        _render_census(report.kids_before, current_kid()),
        "After:",
        _render_census(report.kids_after, current_kid()),
    ]
    if report.failed_row_ids:
        lines.append("Failed row ids (left untouched, investigate before dropping old keys):")
        lines.extend(f"  {row_id}" for row_id in report.failed_row_ids)
    return "\n".join(lines)


@app.command("rewrap-sealed-secrets")
def rewrap_sealed_secrets(
    check: bool = typer.Option(
        False,
        "--check",
        help="Report sealed envelopes per key id (current values + active history) and exit 1 when rows on "
        "non-current keys remain. Read-only.",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Actually rewrite old-kid envelopes to the newest key. Aborts when active history still "
        "carries old-kid envelopes (drain first). Without it, runs a dry-run preview.",
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Skip the confirmation prompt. Required for non-interactive runs."
    ),
    batch_size: int = typer.Option(500, min=1, help="Rows rewritten per transaction. Small batches bound lock time."),
) -> None:
    """Re-encrypt current sealed-secret values to the newest configured key.

    Rotation itself is lazy (prepend the new key; old envelopes keep decrypting). This command is the
    optional hygiene step: rewriting *current subscription values* so the old key can be destroyed
    sooner. History tables (input_states, process_steps) are never touched.

    Drain -> rewrap -> gate:
      1. Prepend the new key to SEALED_SECRETS_FERNET_KEYS and deploy.
      2. Drain: retry active processes to COMPLETED (PUT /resume) or ask the starter to abort
         (PUT /abort). This tool never aborts processes itself.
      3. Preview: `orchestrator secrets rewrap-sealed-secrets` (dry run, no writes).
      4. Apply: `orchestrator secrets rewrap-sealed-secrets --execute` (refuses when active
         history still carries old-kid envelopes, then confirms, rewrites current values batch
         by batch with per-batch verify, resumable on crash).
      5. Gate: `orchestrator secrets rewrap-sealed-secrets --check` until exit 0, re-checked
         immediately before dropping the key (preview vs execute are non-atomic and validators
         re-migrate old envelopes on resume, so history can re-dirty). Quiesce process
         start/resume/callback/keep paths before the final check, then drop the old key, deploy
         and destroy the old key material (escrow a copy until the gate is green).

    CLI Options:
        ```shell
        Options:
            --check          Census only (current values + active history); exit 1 when non-current rows remain.
            --execute        Perform the rewrite (default is a dry run). Aborts when history blocks.
            --yes, -y        Skip confirmation.
            --batch-size N   Rows per transaction [default: 500].
        ```
    """
    if not app_settings.TESTING:
        init_database(app_settings)

    target_kid = current_kid()
    if target_kid is None:
        logger.error("Sealed secrets are disabled (SEALED_SECRETS_FERNET_KEYS is empty)")
        raise typer.Exit(code=2)

    if check:
        census = census_current_values()
        history_census, blocking = census_active_history(target_kid=target_kid)
        logger.info("Sealed envelope census", target_kid=target_kid)
        print("Current subscription values:")  # noqa: T001, T201 - CLI output is the point
        print(_render_census(census, target_kid))  # noqa: T001, T201 - CLI output is the point
        print("Active process history:")  # noqa: T001, T201 - CLI output is the point
        print(_render_census(history_census, target_kid))  # noqa: T001, T201 - CLI output is the point
        dirty = [kid for kid in census if kid != target_kid]
        dirty_history = [kid for kid in history_census if kid != target_kid]
        if blocking:
            print(_render_blocking_processes(blocking))  # noqa: T001, T201 - CLI output is the point
        raise typer.Exit(code=1 if dirty or dirty_history else 0)

    if not execute:
        report = rewrap_current_values(batch_size=batch_size, dry_run=True)
        logger.info("Rewrap dry run finished")
        print(_render_report(report))  # noqa: T001, T201 - CLI output is the point
        print("Re-run with --execute to apply.")  # noqa: T001, T201 - CLI output is the point
        return

    _, blocking = census_active_history(target_kid=target_kid)
    if blocking:
        print(_render_blocking_processes(blocking))  # noqa: T001, T201 - CLI output is the point
        logger.error("Refusing rewrap: active history still carries old-kid envelopes; drain first")
        raise typer.Abort()

    preview = rewrap_current_values(batch_size=batch_size, dry_run=True)
    if preview.scanned == 0:
        print("No sealed values stored; nothing to do.")  # noqa: T001, T201 - CLI output is the point
        return
    print(_render_report(preview))  # noqa: T001, T201 - CLI output is the point
    if not yes and not typer.confirm("Rewrite old-kid envelopes to the newest key?"):
        raise typer.Abort()

    report = rewrap_current_values(batch_size=batch_size, dry_run=False)
    logger.info("Rewrap finished", rewrapped=report.rewrapped, failed=len(report.failed_row_ids))
    print(_render_report(report))  # noqa: T001, T201 - CLI output is the point
    if report.failed_row_ids:
        raise typer.Exit(code=1)
