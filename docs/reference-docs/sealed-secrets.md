# Sealed secrets in forms

Password, token and shared-secret fields must never be stored as cleartext in the database — not in
`input_states`, not in `process_steps.state`, not in resource values. The `SealedSecret` field type gives
you a **password box** in the UI whose value is Fernet-encrypted during form validation, so only
ciphertext (`fernet-v1:<kid>:<token>` envelopes) is ever persisted. Decryption is server-side only,
inside workflow steps.

## Quick start (new instance)

```bash
# 1. Generate a key (44-char urlsafe base64) and configure it everywhere the app runs,
#    including Celery workers (they decrypt inside steps):
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
export SEALED_SECRETS_FERNET_KEYS='["<current-key>"]'

# 2. Deploy, then verify the gate is green:
orchestrator secrets rewrap-sealed-secrets --check; echo "exit=$?"
```

An exit code of `0` with only `current`-marked lines means healthy. Until keys are configured,
sealed secrets are **disabled** and any form using `SealedSecret` fails validation instead of
storing plaintext (fail closed).

## Concepts (30 seconds)

| Term | Meaning |
| --- | --- |
| Envelope | Stored ciphertext string: `fernet-v1:<kid>:<token>`. Never cleartext. |
| `kid` | 8-hex id of the key that sealed the envelope (e.g. `2bacc45f`). Shows *which* key, not the secret. |
| Ring | `SEALED_SECRETS_FERNET_KEYS`, newest first, at most **two** keys: current plus one predecessor during rotation. |
| Fail closed | Anything undecryptable is rejected loudly, never stored or logged. |
| History | `input_states` and `process_steps` rows. **Never rewritten** — audit trail first. |

## Enable sealed secrets

Prerequisites: shell access to run the `orchestrator` CLI against the production database, and a
deploy path for settings on **every** replica — API servers *and* Celery workers. Workers decrypt
inside steps; a worker without the ring fails the step instead of leaking.

```bash
SEALED_SECRETS_FERNET_KEYS='["<current-key>", "<previous-key>"]'
```

At most **two** keys: the current key first, plus one predecessor while rotating. Invalid keys are
rejected at startup (`SEALED_SECRETS_FERNET_KEYS contains an invalid Fernet key`). Keep
`EXPOSE_SETTINGS=false`: the keys are `SecretStr` and masked in `/settings/overview`, but exposing
settings is unnecessary risk.

Fleet rollout order matters: deploy the new ring **everywhere** (servers and workers) *before*
rewrapping. An instance still on the old ring cannot decrypt envelopes minted with the new key and
fails steps that touch them.

## Adopt on existing data (read this before adding the field)

Adding `SealedSecret` to a form does **not** encrypt rows that already hold cleartext. Existing
cleartext stays exactly as it is — readable in the API, as before — until each secret is rotated
through a modify workflow (submit a new value; `null`/omitted keeps the stored one). The rewrap
tool only re-encrypts envelopes, never cleartext.

Procedure per product:

1. Deploy the form change with keys configured.
2. For every subscription, run the modify workflow submitting a fresh secret (this is also the
   moment to change the password at the device, if policy requires).
3. Hunt for leftovers — all three counts must be `0`:

```bash
export PGPASSWORD=<db-password>
for spec in "subscription_instance_values value" "input_states input_state" "process_steps state"; do
  set -- $spec
  psql -h <db-host> -U nwa -d orchestrator-core -tAc \
    "SELECT count(*) FROM $1 WHERE $2::text NOT LIKE 'fernet-v1:%' AND $2::text != 'null'"
done
```

(The `NOT LIKE` filter lists *non-envelope* values for manual review; plain strings like usernames
are expected — you are looking for secrets you meant to seal.)

## Rotation runbook: drain → rewrap → gate

History rows are **never rewritten**, so dropping a key makes every envelope sealed under it
permanently undecryptable — including the history of processes that can still be resumed. The
command gates on two things: *current subscription values* (rewritable) and *active process
history* (not rewritable — drain it first).

Only `completed` and `aborted` histories are ignored. Everything else counts as active,
**including `failed`** and its retryable `inconsistent_data` / `api_unavailable` subtypes, because
those can still be retried (`PUT /resume`, `PUT /resume-all`).

**1. Generate a new key. Prepend it: `'["<new>", "<old>"]'`. Deploy everywhere (servers + workers).**

**2. Drain.** Retry active processes to `COMPLETED` (`PUT /resume`, `PUT /resume-all` for bulk), or
ask the starter to abort the ones nobody will finish (`PUT /abort`). Aborting keeps the process
row for audit while shedding its history. The rewrap tool **never aborts** anything itself.

**3. Check.** A dirty gate looks like this (exit `1` — old-kid rows remain, do not drop the key):

```text
Current subscription values:
  2bacc45f: 1 row(s)  <-- current
  d7336955: 1 row(s)
Active process history:
  2bacc45f: 1 row(s)  <-- current
```

```bash
orchestrator secrets rewrap-sealed-secrets --check; echo "exit=$?"
# exit=1 means old-kid (or undecryptable) rows remain — stop here and drain/retry first.
```

**4. Preview** (dry run, no writes). Note the projection is optimistic: it counts rows that *should*
move; only `--execute` verifies each row by decrypting it:

```text
Dry run (no writes): scanned=2 rewrapped=1 already_current=1 failed=0
Before:
  2bacc45f: 1 row(s)  <-- current
  d7336955: 1 row(s)
After:
  2bacc45f: 2 row(s)  <-- current
Re-run with --execute to apply.
```

**5. Apply.** Re-checks active history and refuses while anything blocks, then rewrites *current
subscription values* batch by batch with per-batch verify (resumable on crash — just rerun the
same command; per-batch transactions). Undecryptable rows are left untouched and reported by row
id only, never with values:

```bash
orchestrator secrets rewrap-sealed-secrets --execute --yes
```

**6. Gate.** Repeat `--check` until exit `0`, and re-run it *immediately before* dropping the key:
preview and execute are not atomic, and any process that starts, resumes, calls back or is kept in
the meantime can re-dirty history. Quiesce those paths for the final check.

**7. Drop the old key, deploy, then destroy the old key material.** Escrow a copy until the final
`--check` is green — once dropped, terminated history shreds: the audit rows stay, the secrets do
not. If you ever need those histories back, the escrowed key restores them (re-add it to the ring).

Exit codes: `0` clean, `1` dirty (rows or blocking processes on non-current keys) or execute
refused/failed, `2` sealed secrets disabled.

There is intentionally no scheduled re-encryption task: a timer that decrypts every secret row
maximizes key exposure for no functional benefit. The command above is manual and audit-logged with
key-id counts and row/process ids only — it never prints secret values.

## Day-to-day operation

**Viewing a secret.** List/detail payloads (REST domain-model, GraphQL detail, process state) mask
every envelope as `••••••` — envelopes never leave the server there. For one-off display
(e.g. click-to-demask in the UI), reveal is explicit and audited:

```bash
curl -X POST http://orchestrator:8080/api/subscriptions/<id>/reveal \
  -H "Content-Type: application/json" -d '{"path":"block.password"}'
# {"value":"...","sensitive":true}
```

`path` is dot-separated into the domain model (find field names in the masked detail payload —
masks keep the names). Every call is audit-logged with subscription id, path, key id and user —
never the value. Note: reveal is available to any authenticated API user; there is no per-role
restriction on top of the global authorization. Non-envelope paths return 404, undecryptable
envelopes 422.

**Monitoring.** The cheapest early warning is the gate itself on a schedule (it is read-only):

```bash
orchestrator secrets rewrap-sealed-secrets --check || alert "sealed-secret gate dirty"
```

**Backup & restore.** Database backups contain envelopes (good — no cleartext). Keep key material
*out* of the same backups: a backup plus its keys decrypts everything. To restore, restore the
database and supply the *same* ring; history sealed under retired keys needs those keys in the
ring to stay readable.

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `--check` exit `1`, old-kid rows remain | Rotation in progress or undrained history | Drain active processes, `--execute`, re-`--check` before dropping any key |
| `--execute` lists failed row ids | Rows no configured key can decrypt | Find which key sealed them (escrow/backups), add it to the ring, rerun; or accept the loss *before* dropping anything |
| Reveal returns 422 | Envelope's key not in the ring | Add the missing key back to the ring (escrow) |
| Reveal returns 404 | Wrong `path`, or field holds no envelope | Compare against the masked domain-model payload for exact field names |
| Subscription detail errors after key removal | `SealedSecret`-annotated domain model + undecryptable stored value (fail closed) | Re-add the retired key to the ring; this is the shredding the runbook warns about |
| `SEALED_SECRETS_FERNET_KEYS contains an invalid Fernet key` at startup | Typo or truncated key (must be 44-char urlsafe base64) | Regenerate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` |
| Secrets visible in logs after setting `LOG_LEVEL=DEBUG` | `pydantic_forms` logs raw inputs at DEBUG (dependency behavior) | Keep production at INFO or above (`pydantic_forms` is pinned to `INFO` in `log_config.py`); `orchestrator.core`'s own validation-error logs mask sealed values at any level |
| `sealed_secret_blank` validation errors | Client sent `""` instead of `null` for keep | UI must submit `null`/omitted for untouched secret fields |

## FAQ

- *Are sealed values searchable?* No — sealed fields (even their names) are excluded from the
  search index, and ciphertext is never embedded in index documents.
- *The UI shows `••••••` with no way to reveal?* The backend ships masking plus the audited
  `/reveal` endpoint; a click-to-demask button is UI work tracked separately.
- *Do I need keys on workers/scheduler?* Yes, everywhere the app runs: steps decrypt at point of
  use, including on Celery workers.
- *Can I use more than two keys?* No — the ring holds at most two (current + one predecessor).
  Startup rejects longer lists.
- *What if a device password itself leaks?* Rotating *keys* re-encrypts the same secret; it does
  not change it. Change the password at the device *and* submit the new value through a modify
  workflow.

## For workflow developers

Declare required secrets as `field: SealedSecret` (blank and null are rejected) and modify-workflow
secrets as `field: SealedSecret | None = None` (`null`/omitted means "keep the stored value", a
value means "rotate"). The UI renders a masked password input (`type="password"`,
`autocomplete="new-password"`) for `format: sealedSecret` fields and never seeds a stored value
into the input, so ciphertext cannot reach the DOM. Use the write-only rotate pattern — **never
prefill from the subscription**:

```python
from orchestrator.core.forms.validators import SealedSecret


class CreateDeviceForm(FormPage):
    username: str
    password: SealedSecret  # required: blank and null are rejected


class ModifyDeviceForm(FormPage):
    username: str = current_username
    # No default from the subscription: null/omitted keeps the stored value, a value rotates it.
    password: SealedSecret | None = None
```

Key semantics:

- Blank is `null`, not `""`. The UI submits `null` for an untouched field. **Empty strings are
  rejected** with a `sealed_secret_blank` validation error; there is no silent `""`-to-`None`
  mapping, because pydantic feeds union members the *original* input, so `SealedSecret | None`
  would never accept `""` anyway. Failing loudly beats an ambiguous store.
- Non-string input (bytes, enums, numbers) is rejected with `sealed_secret_type` instead of being
  coerced into a secret.
- `None`/omitted survives validation as `None`, so state merges and `ProductBlockModel.save()` keep
  the existing database row untouched (`None` values are skipped on save).
- Cleartext encrypts to an envelope *before* `store_input_state` runs.
- A submitted envelope is validated again on resume: envelopes already on the **current** key pass
  through byte-identical (no churn, nothing rewritten), while envelopes on an **older** key are
  conditionally migrated — decrypted with the ring and re-encrypted to the newest key, with a
  round-trip verification. An envelope that no configured key can decrypt fails fast with
  `sealed_secret_undecryptable` instead of being stored or logged.
- In the step that needs the secret, decrypt at the point of use and never return it into state:

```python
from orchestrator.core.forms.validators import decrypt_sealed_secret, resolve_sealed_secret_update

envelope = resolve_sealed_secret_update(user_input.get("password"), subscription.block.password)
secret = decrypt_sealed_secret(envelope)  # use immediately; never log it, never return it
```

- Sealed values never appear in summary tables, at any nesting depth: a value holding an envelope
  renders as `••••••`, plain siblings in mixed lists survive, and formatter output is scanned too
  (a sealed field is masked *before* any custom formatter sees it). Sealed fields are excluded from
  the search index, and validation-error logs mask sealed cleartext while logging everything else
  as usual.

## API presentation

Subscription domain-model (`GET /subscriptions/domain-model/{id}`, GraphQL detail)
and process detail (`current_state`, step `state`/`state_delta`) mask every
envelope as `••••••`. Envelopes never leave the server in list/detail payloads.

To display a secret (e.g. click-to-demask in the UI), call the audited reveal:

```http
POST /api/subscriptions/{id}/reveal
{"path": "block.password"}
```

`path` is dot-separated into the domain model. The server resolves it against
the unmasked model, decrypts server-side and returns the cleartext once
(`{"value": "...", "sensitive": true}`). Every call is audit-logged with
subscription id, path, key id and user — never the value. Non-envelope paths
return 404; undecryptable envelopes return 422.

## Residual risks

- Cleartext transiently exists in the TLS-terminated request body, in server RAM during the single
  validation call, and again when a step decrypts the secret to use it. This matches the standard
  HTTPS-login model; the guarantee covers storage, not RAM.
- `pydantic_forms` itself logs raw `user_inputs` at DEBUG (`post_form` and its translation step), so
  cleartext can still reach the log pipeline at debug level. The `pydantic_forms` logger is pinned to
  `INFO` in `log_config.py` for exactly this reason; override at deploy time only with
  `LOG_LEVEL_PYDANTIC_FORMS=DEBUG` and accept the exposure. The validation-error logs in
  `orchestrator.core` are safe at any level: sealed values are masked — or the inputs omitted
  entirely when the form's sealed fields cannot be resolved — and the logged error message never
  carries field input values.
- A compromised key reads all rows sealed under it. Keep the ring at 1–2 keys, keep keys out of
  backups and log pipelines, and never expose `SEALED_SECRETS_FERNET_KEYS` via settings endpoints.
  API list/detail payloads are masked (`••••••`); use the audited `POST .../reveal` for one-off display.
  Note envelopes encode approximate plaintext length, so treat exfiltrated ciphertext as sensitive.
- Workflow authors can still footgun by logging a decrypted value or returning it into state.
  Decrypt late, use immediately, drop the reference.
