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

from typing import Annotated, Any

import pytest
from cryptography.fernet import Fernet
from pydantic import BaseModel, Field, SecretStr, ValidationError

from orchestrator.core.db.models import RESOURCE_VALUE_LENGTH
from orchestrator.core.forms.summary_form.summary_form import _get_column_values
from orchestrator.core.forms.validators.sealed_secret import (
    MAX_SEALED_PLAINTEXT_BYTES,
    MAX_STORED_ENVELOPE_CHARS,
    SEALED_REDACTED,
    SEALED_SUMMARY_MASK,
    SealedSecret,
    SealedSecretDecryptionError,
    SealedSecretsDisabledError,
    decrypt_sealed_secret,
    encrypt_sealed_secret,
    is_sealed_envelope,
    is_sealed_secret_annotation,
    key_id_for_fernet_key,
    mask_sealed_cleartext,
    redacted_user_inputs,
    resolve_sealed_secret_update,
    sealed_field_names,
)
from orchestrator.core.search.indexing.traverse import BaseTraverser
from orchestrator.core.settings import AppSettings, app_settings
from pydantic_forms.core import FormPage

SECRET = "s3cr3t-cleartext-password"  # noqa: S105 - test fixture, not a credential
ENVELOPE = "fernet-v1:0123abcd:QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="


class SecretForm(FormPage):
    username: str
    password: Annotated[str, Field(json_schema_extra={"format": "sealedSecret", "writeOnly": True})] = ""


class PlainForm(FormPage):
    username: str
    note: str = ""


class NestedInner(BaseModel):
    token: Annotated[str, Field(json_schema_extra={"format": "sealedSecret"})] = ""


class NestedForm(FormPage):
    title: str
    inner: NestedInner | None = None


class OptionalSecretForm(FormPage):
    username: str
    password: Annotated[str, Field(json_schema_extra={"format": "sealedSecret"})] | None = None


def single_page(form_cls: type[FormPage]):
    def gen(state: dict[str, Any]):
        data = yield form_cls
        return {"data": data}

    return gen


def test_is_sealed_envelope_accepts_only_wellformed_envelopes():
    assert is_sealed_envelope(ENVELOPE)
    assert not is_sealed_envelope(SECRET)
    assert not is_sealed_envelope("")
    assert not is_sealed_envelope(None)
    assert not is_sealed_envelope(123)
    assert not is_sealed_envelope("fernet-v1:short:x")
    assert not is_sealed_envelope("fernet-v2:0123abcd:QUJD")
    assert not is_sealed_envelope(SEALED_REDACTED)


@pytest.mark.parametrize(
    ("form_cls", "expected"),
    [
        (SecretForm, {"password"}),
        (PlainForm, set()),
        (NestedForm, {"token"}),
        (OptionalSecretForm, {"password"}),
    ],
)
def test_sealed_field_names_from_single_class(form_cls, expected):
    names, resolved = sealed_field_names(form_cls, {})
    assert resolved is True
    assert names == expected


def test_sealed_field_names_walks_multi_page_generator():
    def gen(state):
        first = yield SecretForm
        second = yield PlainForm
        return {"first": first, "second": second}

    names, resolved = sealed_field_names(gen, {}, [{"username": "u", "password": SECRET}, {"username": "u"}])
    assert resolved is True
    assert names == {"password"}


def test_sealed_field_names_none_and_unresolvable():
    names, resolved = sealed_field_names(None, {})
    assert (names, resolved) == (frozenset(), True)

    def broken(state):
        raise RuntimeError("nope")

    names, resolved = sealed_field_names(broken, {}, [{"username": "u"}])
    assert resolved is False


def test_mask_sealed_cleartext_masks_only_sealed_cleartext():
    pages = [{"username": "alice", "password": SECRET, "note": SECRET}]
    masked = mask_sealed_cleartext(pages, frozenset({"password"}))
    assert masked == [{"username": "alice", "password": SEALED_REDACTED, "note": SECRET}]
    # Input never mutated
    assert pages[0]["password"] == SECRET


def test_mask_sealed_cleartext_leaves_envelopes_and_keep_markers():
    pages = [{"password": ENVELOPE}, {"password": None}, {"password": ""}]
    assert mask_sealed_cleartext(pages, frozenset({"password"})) == pages


def test_mask_sealed_cleartext_recurses_into_nested_structures():
    pages = [{"outer": {"token": SECRET, "label": SECRET}, "items": [{"token": SECRET, "n": 1}]}]
    masked = mask_sealed_cleartext(pages, frozenset({"token"}))
    assert masked == [
        {"outer": {"token": SEALED_REDACTED, "label": SECRET}, "items": [{"token": SEALED_REDACTED, "n": 1}]}
    ]


def test_mask_sealed_cleartext_masks_subtree_under_sealed_key():
    pages = [{"creds": {"user": "alice", "pw": SECRET}}]
    masked = mask_sealed_cleartext(pages, frozenset({"creds"}))
    assert masked == [{"creds": {"user": SEALED_REDACTED, "pw": SEALED_REDACTED}}]


def test_redacted_user_inputs_end_to_end():
    gen = single_page(SecretForm)
    masked = redacted_user_inputs(gen, {}, [{"username": "alice", "password": SECRET}])
    assert masked == [{"username": "alice", "password": SEALED_REDACTED}]


def test_redacted_user_inputs_no_sealed_fields_logs_as_is():
    gen = single_page(PlainForm)
    original = [{"username": "alice", "note": "hello"}]
    assert redacted_user_inputs(gen, {}, original) == original


def test_redacted_user_inputs_unresolvable_omits_values():
    def broken(state):
        raise RuntimeError("nope")

    assert redacted_user_inputs(broken, {}, [{"password": SECRET}]) == {"omitted": "unresolved form schema"}


def test_redacted_user_inputs_empty_inputs():
    assert redacted_user_inputs(single_page(SecretForm), {}, []) == []
    assert redacted_user_inputs(single_page(SecretForm), {}, None) == []


def test_is_sealed_secret_annotation():
    sealed = Annotated[str, Field(json_schema_extra={"format": "sealedSecret"})]
    plain = Annotated[str, Field(json_schema_extra={"format": "custom"})]
    assert is_sealed_secret_annotation(sealed) is True
    assert is_sealed_secret_annotation(sealed | None) is True
    assert is_sealed_secret_annotation(list[sealed]) is True
    assert is_sealed_secret_annotation(plain) is False
    assert is_sealed_secret_annotation(str) is False
    assert is_sealed_secret_annotation(None) is False
    assert is_sealed_secret_annotation(NestedInner) is True


# --- Fernet envelope round-trip (commit 2) ---

KEY_A = Fernet.generate_key().decode()
KEY_B = Fernet.generate_key().decode()


@pytest.fixture()
def sealed_keys(monkeypatch):
    """Configure a single sealed-secret key, restored after the test."""
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    return [KEY_A]


@pytest.fixture()
def rotated_keys(monkeypatch):
    """Configure a rotated ring: newest first."""
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B), SecretStr(KEY_A)])
    return [KEY_B, KEY_A]


def test_encrypt_decrypt_roundtrip(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    assert is_sealed_envelope(envelope)
    assert envelope.startswith(f"fernet-v1:{key_id_for_fernet_key(KEY_A)}:")
    assert SECRET not in envelope
    assert decrypt_sealed_secret(envelope) == SECRET


def test_encrypt_randomizes_envelopes(sealed_keys):
    assert encrypt_sealed_secret(SECRET) != encrypt_sealed_secret(SECRET)


def test_encrypt_fails_closed_when_disabled(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [])
    with pytest.raises(SealedSecretsDisabledError):
        encrypt_sealed_secret(SECRET)


def test_encrypt_rejects_oversize_plaintext(sealed_keys):
    with pytest.raises(ValueError, match="exceeds"):
        encrypt_sealed_secret("x" * (MAX_SEALED_PLAINTEXT_BYTES + 1))


def test_encrypt_envelope_fits_storage_column(sealed_keys):
    envelope = encrypt_sealed_secret("x" * MAX_SEALED_PLAINTEXT_BYTES)
    assert len(envelope) <= MAX_STORED_ENVELOPE_CHARS
    assert len(envelope) < MAX_STORED_ENVELOPE_CHARS


def test_storage_cap_matches_resource_value_column_length():
    assert MAX_STORED_ENVELOPE_CHARS == RESOURCE_VALUE_LENGTH


def test_decrypt_old_envelope_after_rotation(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    old_envelope = encrypt_sealed_secret(SECRET)
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B), SecretStr(KEY_A)])
    assert decrypt_sealed_secret(old_envelope) == SECRET


def test_decrypt_prefers_kid_match(rotated_keys):
    new_envelope = encrypt_sealed_secret(SECRET)
    assert new_envelope.startswith(f"fernet-v1:{key_id_for_fernet_key(KEY_B)}:")
    assert decrypt_sealed_secret(new_envelope) == SECRET


def test_decrypt_rejects_garbage_and_unknown_versions(rotated_keys):
    with pytest.raises(SealedSecretDecryptionError):
        decrypt_sealed_secret("not-an-envelope")
    with pytest.raises(SealedSecretDecryptionError):
        decrypt_sealed_secret("fernet-v9:0123abcd:QUJD")
    with pytest.raises(SealedSecretDecryptionError):
        decrypt_sealed_secret(encrypt_sealed_secret(SECRET)[:-4] + "AAAA")


def test_resolve_sealed_secret_update_keep_vs_rotate():
    assert resolve_sealed_secret_update(None, ENVELOPE) == ENVELOPE
    assert resolve_sealed_secret_update("", ENVELOPE) == ENVELOPE
    assert resolve_sealed_secret_update(ENVELOPE, None) == ENVELOPE
    assert resolve_sealed_secret_update(None, None) is None


# --- SealedSecret field type in forms ---


class TypedSecretForm(FormPage):
    username: str
    password: SealedSecret


class TypedOptionalSecretForm(FormPage):
    username: str
    password: SealedSecret | None = None


def test_sealed_secret_field_encrypts_during_validation(sealed_keys):
    form = TypedSecretForm(username="alice", password=SECRET)
    dumped = form.model_dump()
    assert is_sealed_envelope(dumped["password"])
    assert SECRET not in dumped["password"]
    assert dumped["username"] == "alice"


def test_sealed_secret_field_rejects_empty_when_required(sealed_keys):
    with pytest.raises(ValidationError):
        TypedSecretForm(username="alice", password="")
    with pytest.raises(ValidationError):
        TypedSecretForm(username="alice", password=None)


def test_sealed_secret_optional_null_means_keep(sealed_keys):
    assert TypedOptionalSecretForm(username="alice", password=None).model_dump()["password"] is None
    assert TypedOptionalSecretForm(username="alice").model_dump()["password"] is None


def test_sealed_secret_optional_empty_string_rejected_loudly(sealed_keys):
    with pytest.raises(ValidationError, match="sealed_secret_blank"):
        TypedOptionalSecretForm(username="alice", password="")


def test_sealed_secret_field_accepts_envelope_idempotently(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    form = TypedSecretForm(username="alice", password=envelope)
    assert form.model_dump()["password"] == envelope


def test_sealed_secret_field_current_envelope_has_no_churn(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    form = TypedSecretForm(username="alice", password=envelope)
    assert form.model_dump()["password"] == envelope


def test_sealed_secret_field_upgrades_old_kid_envelope(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    old_envelope = encrypt_sealed_secret(SECRET)
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B), SecretStr(KEY_A)])
    form = TypedSecretForm(username="alice", password=old_envelope)
    fresh = form.model_dump()["password"]
    assert fresh != old_envelope
    assert is_sealed_envelope(fresh)
    assert fresh.startswith(f"fernet-v1:{key_id_for_fernet_key(KEY_B)}:")
    assert decrypt_sealed_secret(fresh) == SECRET


def test_sealed_secret_field_rejects_envelope_when_disabled(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    envelope = encrypt_sealed_secret(SECRET)
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [])
    with pytest.raises(ValidationError, match="sealed_secret_undecryptable"):
        TypedSecretForm(username="alice", password=envelope)


def test_sealed_secret_field_rejects_foreign_envelope(sealed_keys):
    foreign_key = Fernet.generate_key().decode()
    orphan = f"fernet-v1:{key_id_for_fernet_key(foreign_key)}:{Fernet(foreign_key.encode()).encrypt(b'x').decode()}"
    with pytest.raises(ValidationError, match="sealed_secret_undecryptable"):
        TypedSecretForm(username="alice", password=orphan)


def test_sealed_secret_field_rejects_tampered_old_envelope(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    old_envelope = encrypt_sealed_secret(SECRET)
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B), SecretStr(KEY_A)])
    tampered = old_envelope[:-4] + "AAAA"
    with pytest.raises(ValidationError, match="sealed_secret_undecryptable"):
        TypedSecretForm(username="alice", password=tampered)


def test_sealed_secret_field_current_envelope_passes_without_reverify(sealed_keys):
    # No-churn contract: current-kid envelopes are trusted as-is (tampering surfaces at
    # decrypt time inside the workflow step, not at form validation).
    envelope = encrypt_sealed_secret(SECRET)
    tampered = envelope[:-4] + "AAAA"
    form = TypedSecretForm(username="alice", password=tampered)
    assert form.model_dump()["password"] == tampered


@pytest.mark.parametrize("bad_value", [b"bytes-secret", 123, ["x"], {"k": "v"}])
def test_sealed_secret_field_rejects_non_string_inputs(sealed_keys, bad_value):
    with pytest.raises(ValidationError, match="sealed_secret_type"):
        TypedSecretForm(username="alice", password=bad_value)


def test_sealed_secret_field_rejects_non_string_enum_coercion(sealed_keys):
    from enum import Enum

    class Choice(str, Enum):
        OPTION = "option-value"

    with pytest.raises(ValidationError, match="sealed_secret_type"):
        TypedSecretForm(username="alice", password=Choice.OPTION)


def test_decrypt_rejects_non_utf8_payload(sealed_keys):
    raw_key = app_settings.SEALED_SECRETS_FERNET_KEYS[0].get_secret_value().encode()
    token = Fernet(raw_key).encrypt(b"\xff\xfe\x00invalid-utf8").decode()
    envelope = f"fernet-v1:{key_id_for_fernet_key(raw_key.decode())}:{token}"
    assert is_sealed_envelope(envelope)
    with pytest.raises(SealedSecretDecryptionError):
        decrypt_sealed_secret(envelope)


def test_sealed_secret_field_rejects_non_utf8_old_envelope(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_A)])
    raw_a = KEY_A.encode()
    token = Fernet(raw_a).encrypt(b"\xff\xfe\x00invalid-utf8").decode()
    old_envelope = f"fernet-v1:{key_id_for_fernet_key(KEY_A)}:{token}"
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(KEY_B), SecretStr(KEY_A)])
    with pytest.raises(ValidationError, match="sealed_secret_undecryptable"):
        TypedSecretForm(username="alice", password=old_envelope)


def test_sealed_secret_field_fails_closed_when_disabled(monkeypatch):
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [])
    with pytest.raises(ValidationError):
        TypedSecretForm(username="alice", password=SECRET)


def test_sealed_field_names_finds_typed_fields():
    names, resolved = sealed_field_names(TypedSecretForm, {})
    assert (names, resolved) == (frozenset({"password"}), True)
    names, resolved = sealed_field_names(TypedOptionalSecretForm, {})
    assert (names, resolved) == (frozenset({"password"}), True)


# --- Settings validation ---


def test_settings_rejects_too_many_keys():
    keys = [SecretStr(Fernet.generate_key().decode()) for _ in range(3)]
    with pytest.raises(ValueError, match="at most 2"):
        AppSettings.validate_sealed_secrets_fernet_keys(keys)


def test_settings_rejects_invalid_key():
    with pytest.raises(ValueError, match="invalid Fernet key"):
        AppSettings.validate_sealed_secrets_fernet_keys([SecretStr("not-a-key")])


def test_settings_accepts_empty_and_valid_keys():
    assert AppSettings.validate_sealed_secrets_fernet_keys([]) == []
    keys = [SecretStr(KEY_A)]
    assert AppSettings.validate_sealed_secrets_fernet_keys(keys) == keys


# --- Summary masking ---


def test_summary_masks_sealed_envelopes(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    values = _get_column_values({"name": "alice", "password": envelope}, {})
    assert values == ["alice", SEALED_SUMMARY_MASK]
    assert SECRET not in str(values)
    assert envelope not in str(values)


def test_summary_masks_envelopes_inside_lists(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    values = _get_column_values({"tokens": [envelope, "plain"]}, {})
    assert values == [str([SEALED_SUMMARY_MASK, "plain"])]


def test_summary_masks_nested_dict_envelope(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    values = _get_column_values({"config": {"password": envelope, "user": "alice"}}, {})
    assert values == [SEALED_SUMMARY_MASK]
    assert SECRET not in str(values)
    assert envelope not in str(values)


def test_summary_masks_tuple_and_set_envelopes(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    values = _get_column_values({"tokens": (envelope, "plain")}, {})
    assert values == [str([SEALED_SUMMARY_MASK, "plain"])]
    assert envelope not in str(values)
    values = _get_column_values({"tokens": {envelope, "plain"}}, {})
    assert SEALED_SUMMARY_MASK in values[0]
    assert "plain" in values[0]
    assert envelope not in values[0]


def test_summary_masks_deeply_nested_envelope(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    values = _get_column_values({"outer": {"inner": [envelope]}}, {})
    assert values == [SEALED_SUMMARY_MASK]
    assert envelope not in str(values)


def test_summary_scans_formatter_output(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    options = {"formatter": {"password": lambda v: iter([("password", v)])}}
    values = _get_column_values({"password": "plain-input"}, options)
    assert values == ["plain-input"]
    echo_options = {"formatter": {"token": lambda v: iter([("token", envelope)])}}
    values = _get_column_values({"token": "anything"}, echo_options)
    assert values == [SEALED_SUMMARY_MASK]
    assert envelope not in str(values)


def test_summary_sealed_short_circuits_formatter(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    seen: list = []

    def spy_formatter(v):
        seen.append(v)
        yield "password", v

    values = _get_column_values({"password": envelope}, {"formatter": {"password": spy_formatter}})
    assert values == [SEALED_SUMMARY_MASK]
    assert seen == []
    assert envelope not in str(values)


# --- Search index exclusion ---


class IndexModel(BaseModel):
    title: str
    password: SealedSecret | None = None


def test_traverse_skips_sealed_fields(sealed_keys):
    envelope = encrypt_sealed_secret(SECRET)
    fields = list(BaseTraverser.traverse(IndexModel(title="t", password=envelope), "root"))
    paths = [field.path for field in fields]
    assert "root.title" in paths
    assert not [path for path in paths if "password" in path]
    assert not any(SECRET in str(field.value) for field in fields)
    assert not any(envelope in str(field.value) for field in fields)
