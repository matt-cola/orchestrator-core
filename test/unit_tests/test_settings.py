# Copyright 2019-2026 SURF, GÉANT.
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

import json

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError

from orchestrator.core.services.settings_env_variables import expose_settings, get_all_exposed_settings
from orchestrator.core.settings import AppSettings
from orchestrator.core.targets import Target


def test_celery_target_queues_defaults_to_empty_mapping():
    assert AppSettings().CELERY_TARGET_QUEUES == {}


def test_celery_target_queues_env_var_json_round_trip(monkeypatch):
    """Enum-keyed dict must parse from the JSON env-var source (pydantic-settings v2 smoke test)."""
    monkeypatch.setenv("CELERY_TARGET_QUEUES", json.dumps({"RECONCILE": "reconcile", "VALIDATE": "validate"}))

    settings = AppSettings()

    assert settings.CELERY_TARGET_QUEUES == {Target.RECONCILE: "reconcile", Target.VALIDATE: "validate"}


@pytest.mark.parametrize(
    "value",
    [
        pytest.param({"DOES_NOT_EXIST": "some-queue"}, id="unknown-target-key"),
        pytest.param({"RECONCILE": ""}, id="empty-queue-name"),
        pytest.param({"RECONCILE": "   "}, id="whitespace-only-queue-name"),
    ],
)
def test_celery_target_queues_rejects_invalid_mapping(value):
    with pytest.raises(ValidationError):
        AppSettings(CELERY_TARGET_QUEUES=value)


def test_celery_target_queues_rejects_invalid_env_var_at_startup(monkeypatch):
    monkeypatch.setenv("CELERY_TARGET_QUEUES", json.dumps({"NOT_A_TARGET": "queue"}))

    with pytest.raises(ValidationError):
        AppSettings()


# --- Sealed-secret key masking in exposed settings ---


def test_sealed_secret_keys_not_exposed_by_default():
    assert AppSettings().EXPOSE_SETTINGS is False


def test_sealed_secret_key_list_masks_in_model_dump():
    key = Fernet.generate_key().decode()
    dumped = AppSettings(SEALED_SECRETS_FERNET_KEYS=[key]).model_dump()
    assert key not in str(dumped)
    assert all(isinstance(entry, SecretStr) for entry in dumped["SEALED_SECRETS_FERNET_KEYS"])


def test_sealed_secret_key_list_masks_in_exposed_settings_endpoint_payload():
    """list[SecretStr] must not leak raw keys through /settings/overview (env_value: Any)."""
    key = Fernet.generate_key().decode()
    settings = AppSettings(SEALED_SECRETS_FERNET_KEYS=[key], EXPOSE_SETTINGS=True)
    registry_name = "test_exposed_app_settings"
    expose_settings(registry_name, settings)
    try:
        exposed = next(item for item in get_all_exposed_settings() if item.name == registry_name)
        keys = next(v for v in exposed.variables if v.env_name == "SEALED_SECRETS_FERNET_KEYS")
        assert key not in str(keys.env_value)
        assert key not in exposed.model_dump_json()
    finally:
        from orchestrator.core.services.settings_env_variables import EXPOSED_ENV_SETTINGS_REGISTRY

        EXPOSED_ENV_SETTINGS_REGISTRY.pop(registry_name, None)
