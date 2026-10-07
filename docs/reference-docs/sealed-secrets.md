# Sealed secrets in forms

Password, token and shared-secret fields must never be stored as cleartext in the database — not in
`input_states`, not in `process_steps.state`, not in resource values. The `SealedSecret` field type gives
you a **password box** in the UI whose value is Fernet-encrypted during form validation, so only
ciphertext (`fernet-v1:<kid>:<token>` envelopes) is ever persisted. Decryption is server-side only,
inside workflow steps.

## Declaring a secret field

```python
from orchestrator.core.forms.validators import SealedSecret


class CreateDeviceForm(FormPage):
    username: str
    password: SealedSecret  # required: blank and null are rejected
```

Modify workflows use the write-only rotate pattern — **never prefill from the subscription**:

```python
class ModifyDeviceForm(FormPage):
    username: str = current_username
    # No default from the subscription: null/omitted keeps the stored value, a value rotates it.
    password: SealedSecret | None = None
```

The UI renders a masked password input (`type="password"`, `autocomplete="new-password"`) for
`format: sealedSecret` fields and never seeds a stored value into the input, so ciphertext cannot
reach the DOM.

Key semantics:

- Blank is `null`, not `""`. The UI submits `null` for an untouched field. **Empty strings are
  rejected** with a `sealed_secret_blank` validation error; there is no silent `""`-to-`None` mapping,
  because pydantic feeds union members the *original* input, so `SealedSecret | None` would never
  accept `""` anyway. Failing loudly beats an ambiguous store.
- Non-string input (bytes, enums, numbers) is rejected with `sealed_secret_type` instead of being
  coerced into a secret.
- `None`/omitted survives validation as `None`, so state merges and `ProductBlockModel.save()` keep the
  existing database row untouched (`None` values are skipped on save).
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

## Configuration

Sealed secrets are **disabled** until keys are configured — any form using `SealedSecret` then fails
validation instead of storing plaintext (fail closed). An already-stored envelope submitted while
disabled is also rejected, rather than being round-tripped blind:

```bash
SEALED_SECRETS_FERNET_KEYS='["<current-key>", "<previous-key>"]'
```

Each entry is a standard Fernet key (44-char urlsafe base64; generate with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
At most **two** keys may be listed: the current key first, plus one predecessor during rotation.
Invalid keys are rejected at startup. Keep `EXPOSE_SETTINGS=false`: the keys are `SecretStr` and
masked in `/settings/overview`, but exposing settings is unnecessary risk.

## Rotation runbook: drain → rewrap → gate

History rows (`input_states`, `process_steps`) are **never rewritten**, so dropping a key makes every
envelope sealed under it permanently undecryptable — including the history of processes that can
still be resumed. The command therefore gates on two things: *current subscription values* (rewritable)
and *active process history* (not rewritable, so it must be drained first).

Only `completed` and `aborted` histories are ignored by the gate. Everything else counts as active,
**including `failed`** and its retryable `inconsistent_data` / `api_unavailable` subtypes, because
those can still be retried (`PUT /resume`, `PUT /resume-all`).

1. Generate a new key. Prepend it: `'["<new>", "<old>"]'`. Deploy.
2. **Drain.** Retry active processes until they reach `COMPLETED` (`PUT /resume`, `PUT /resume-all`),
   or ask the starter to abort the ones nobody will finish (`PUT /abort`). Aborting keeps the process
   row for audit while shedding its history, which is exactly the tradeoff the gate accepts for
   terminated work. The rewrap tool **never aborts** anything itself.
3. Preview: `orchestrator secrets rewrap-sealed-secrets` (dry run, no writes).
4. Apply: `orchestrator secrets rewrap-sealed-secrets --execute`. It re-checks active history and
   refuses to run while anything blocks, then rewrites *current subscription values* batch by batch
   with per-batch verify (resumable on crash, per-batch transactions).
5. **Gate.** `orchestrator secrets rewrap-sealed-secrets --check` until exit 0. Re-run it
   *immediately before* dropping the key: preview and execute are not atomic, the keyset batch order
   is not stable, and any process that starts, resumes, calls back or is kept in the meantime can
   re-dirty history. Quiesce those paths for the final check.
6. Drop the old key, deploy, then destroy the old key material. Escrow a copy until the final `--check`
   is green — once dropped, terminated history shreds: the audit rows stay, the secrets do not.

Exit codes: `0` clean, `1` dirty (rows or blocking processes on non-current keys), `2` sealed
secrets disabled.

There is intentionally no scheduled re-encryption task: a timer that decrypts every secret row
maximizes key exposure for no functional benefit. The command above is manual and audit-logged with
key-id counts and row/process ids only — it never prints secret values.

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
- Envelopes leak approximate plaintext length if exfiltrated from the database —
  keep keys out of backups and log pipelines, and never expose
  `SEALED_SECRETS_FERNET_KEYS` via settings endpoints. API list/detail payloads
  are masked (`••••••`); use the audited `POST .../reveal` for one-off display.
- Workflow authors can still footgun by logging a decrypted value or returning it into state.
  Decrypt late, use immediately, drop the reference.
