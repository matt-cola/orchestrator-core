# Sealed secrets in forms

Password, token and shared-secret fields must never be stored as cleartext in the database — not in
`input_states`, not in `process_steps.state`, not in resource values. The `SealedSecret` field type gives
you a normal password box in the UI whose value is Fernet-encrypted during form validation, so only
ciphertext (`fernet-v1:<kid>:<token>` envelopes) is ever persisted. Decryption is server-side only,
inside workflow steps.

## Declaring a secret field

```python
from orchestrator.core.forms.validators import SealedSecret

class CreateDeviceForm(FormPage):
    username: str
    password: SealedSecret  # required: blank and null are rejected
```

Modify workflows use the write-only rotate pattern — never prefill from the subscription:

```python
class ModifyDeviceForm(FormPage):
    username: str = current_username
    # No default from the subscription: null/omitted keeps the stored value, a value rotates it.
    password: SealedSecret | None = None
```

Key semantics:

- The UI renders a password input and submits `null` for a blank field. **Empty strings are rejected**
  with a `sealed_secret_blank` validation error — clients must send `null` (or omit the key) for keep.
- `None`/omitted survives validation as `None`, so state merges and `ProductBlockModel.save()` keep the
  existing database row untouched (`None` values are skipped on save).
- A submitted value encrypts to an envelope *before* `store_input_state` runs; re-submitting an
  envelope passes through unchanged (idempotent re-validation on resume).
- In the step that needs the secret, decrypt at the point of use and never return it into state:

```python
from orchestrator.core.forms.validators import decrypt_sealed_secret, resolve_sealed_secret_update

envelope = resolve_sealed_secret_update(user_input.get("password"), subscription.block.password)
secret = decrypt_sealed_secret(envelope)  # use immediately; never log it, never return it
```

- Sealed values never appear in summary tables (rendered as `••••••`) and are excluded from the
  search index. Validation-error logs mask sealed cleartext and log everything else as usual.

## Configuration

Sealed secrets are **disabled** until keys are configured — any form using `SealedSecret` then fails
validation instead of storing plaintext (fail closed):

```bash
SEALED_SECRETS_FERNET_KEYS='["<current-key>", "<previous-key>"]'
```

Each entry is a standard Fernet key (44-char urlsafe base64; generate with
`python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`).
At most **two** keys may be listed: the current key first, plus one predecessor during rotation.
Invalid keys are rejected at startup.

## Rotation runbook

History rows (`input_states`, `process_steps`) are **never rewritten**. Rotation is lazy:

1. Generate a new key. Prepend it: `'["<new>", "<old>"]'`. Deploy.
2. Preview: `orchestrator secrets rewrap-sealed-secrets` (dry run, no writes).
3. Apply: `orchestrator secrets rewrap-sealed-secrets --execute` (confirms, rewrites current
   subscription values batch by batch with per-batch verify, resumable on crash).
4. Gate: `orchestrator secrets rewrap-sealed-secrets --check` (exit 0 when no rows remain on old
   keys). **Before dropping the old key:** `--check` covers current subscription values only.
   History rows (`input_states`, `process_steps`) still carry envelopes sealed under `<old>` and
   are never rewritten — removing the key from the ring makes those historical envelopes
   **permanently undecryptable**. Drop `<old>` only when decrypting history is no longer required,
   then deploy and destroy the old key material.

There is intentionally no scheduled re-encryption task: a timer that decrypts every secret row
maximizes key exposure for no functional benefit. The command above is manual and audited, rewrites
*current subscription values only* (never history), and reports failed row ids without ever printing
secret values.

## Residual risks

- Cleartext transiently exists in the TLS-terminated request body, in server RAM during the single
  validation call, and again when a step decrypts the secret to use it. This matches the standard
  HTTPS-login model; the guarantee covers storage, not RAM.
- At `LOG_LEVEL=DEBUG`, `pydantic_forms` itself logs raw `user_inputs` (in `post_form` and its
  translation step), so cleartext can still reach the log pipeline at debug level. Keep production
  log level at INFO or above. The validation-error logs in `orchestrator.core` are safe at any
  level: sealed values are masked — or the inputs omitted entirely when the form's sealed fields
  cannot be resolved — and the logged error message never carries field input values.
- A compromised key reads all rows sealed under it. Keep the ring at 1–2 keys, keep keys out of
  backups and log pipelines, and never expose `SEALED_SECRETS_FERNET_KEYS` via settings endpoints.
- Envelopes leak approximate plaintext length and are visible to anyone with database or API read
  access — RBAC remains the outer wall.
- Workflow authors can still footgun by logging a decrypted value or returning it into state.
  Decrypt late, use immediately, drop the reference.
