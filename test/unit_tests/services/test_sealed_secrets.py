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
from orchestrator.core.services.sealed_secrets import (
    MALFORMED_KID,
    _rewrap_batch,
    census_kids,
    current_kid,
    envelope_kid,
    rewrap_envelope,
)
from orchestrator.core.settings import app_settings

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
