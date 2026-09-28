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
2. New submissions encrypt under `<new>` (envelope key ids tell them apart). Old envelopes keep
   decrypting while `<old>` is listed. No downtime; suspended/failed processes stay resumable.
3. After the grace period (no current-value rows reference the old key id, or per policy N days),
   remove `<old>` and deploy. Destroy the old key material.

There is intentionally no scheduled re-encryption task: a timer that decrypts every secret row
maximizes key exposure for no functional benefit. If policy requires bounded old-key lifetime, run a
manual, audited rewrap of *current subscription values only* during the rotation window.

## Residual risks

- Cleartext transiently exists in the TLS-terminated request body, in server RAM during the single
  validation call, and again when a step decrypts the secret to use it. This matches the standard
  HTTPS-login model; the guarantee covers storage, not RAM.
- A compromised key reads all rows sealed under it. Keep the ring at 1–2 keys, keep keys out of
  backups and log pipelines, and never expose `SEALED_SECRETS_FERNET_KEYS` via settings endpoints.
- Envelopes leak approximate plaintext length and are visible to anyone with database or API read
  access — RBAC remains the outer wall.
- Workflow authors can still footgun by logging a decrypted value or returning it into state.
  Decrypt late, use immediately, drop the reference.
