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

from unittest.mock import patch
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet
from fastapi.exceptions import HTTPException
from pydantic import SecretStr

from orchestrator.core.forms.validators.sealed_secret import SEALED_SUMMARY_MASK, encrypt_sealed_secret
from orchestrator.core.settings import app_settings

SECRET = "s3cr3t-cleartext-password"  # noqa: S105 - test fixture, not a credential


@pytest.fixture()
def sealed_key(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(key)])
    return key


def _mock_domain(envelope):
    return {"subscription_id": "x", "block": {"password": envelope, "username": "alice"}}


async def test_reveal_returns_plaintext(sealed_key):
    from orchestrator.core.api.api_v1.endpoints.subscriptions import subscription_reveal_sealed_secret
    from orchestrator.core.schemas.subscription import SealedSecretRevealRequest

    envelope = encrypt_sealed_secret(SECRET)
    with (
        patch("orchestrator.core.domain.base.SubscriptionModel.from_subscription", return_value=None),
        patch(
            "orchestrator.core.services.subscriptions.build_domain_model",
            return_value=_mock_domain(envelope),
        ),
    ):
        response = await subscription_reveal_sealed_secret(
            uuid4(), SealedSecretRevealRequest(path="block.password"), None
        )
    assert response.value == SECRET
    assert response.sensitive is True


async def test_reveal_masks_envelopes_in_domain_model(sealed_key):
    envelope = encrypt_sealed_secret(SECRET)
    unmasked = _mock_domain(envelope)
    with (
        patch("orchestrator.core.utils.get_subscription_dict.SubscriptionModel.from_subscription", return_value=None),
        patch("orchestrator.core.utils.get_subscription_dict.build_extended_domain_model", return_value=unmasked),
        patch("orchestrator.core.utils.get_subscription_dict._generate_etag", return_value="etag"),
    ):
        from orchestrator.core.utils.get_subscription_dict import get_subscription_dict

        masked, _ = await get_subscription_dict(uuid4())
    assert masked["block"]["password"] == SEALED_SUMMARY_MASK
    assert masked["block"]["username"] == "alice"
    assert envelope not in str(masked)


async def test_reveal_404_for_non_envelope_path(sealed_key):
    from orchestrator.core.api.api_v1.endpoints.subscriptions import subscription_reveal_sealed_secret
    from orchestrator.core.schemas.subscription import SealedSecretRevealRequest

    with (
        patch("orchestrator.core.domain.base.SubscriptionModel.from_subscription", return_value=None),
        patch(
            "orchestrator.core.services.subscriptions.build_domain_model",
            return_value=_mock_domain("plain-not-envelope"),
        ),
    ):
        with pytest.raises(HTTPException) as exc_info:
            await subscription_reveal_sealed_secret(uuid4(), SealedSecretRevealRequest(path="block.password"), None)
    assert exc_info.value.status_code == 404


async def test_reveal_422_for_blank_path(sealed_key):
    from orchestrator.core.api.api_v1.endpoints.subscriptions import subscription_reveal_sealed_secret
    from orchestrator.core.schemas.subscription import SealedSecretRevealRequest

    with pytest.raises(HTTPException) as exc_info:
        await subscription_reveal_sealed_secret(uuid4(), SealedSecretRevealRequest(path="  "), None)
    assert exc_info.value.status_code == 422


def test_reveal_requires_auth_by_default(test_client, sealed_key):
    response = test_client.post(f"/api/subscriptions/{uuid4()}/reveal", json={"path": "block.password"})
    assert response.status_code in (401, 403)
