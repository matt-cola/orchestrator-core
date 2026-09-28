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

"""End-to-end sealed-secret tests: storage guarantee and validation-error log redaction.

Runs real multi-page form workflows through ``create_process``. The form generators follow the
standard pattern of calling ``.model_dump()`` on the previous page's data before yielding the
next page, so the redaction walk must advance exactly like ``post_form`` does. Log assertions
require the structlog-to-stdlib bridge that the integration conftest installs on app boot.

The redaction tests scope the ``pydantic_forms`` logger to INFO: the test environment runs at
LOG_LEVEL=debug, and ``pydantic_forms`` itself logs raw ``user_inputs`` at DEBUG (``post_form``
and the translation step). Production runs at INFO or above; that dependency-level residual risk
is documented in docs/reference-docs/sealed-secrets.md.
"""

import logging

import pytest
from cryptography.fernet import Fernet
from pydantic import Field, SecretStr
from sqlalchemy import select

from orchestrator.core.db import InputStateTable, db
from orchestrator.core.forms.validators import SealedSecret, is_sealed_envelope
from orchestrator.core.settings import app_settings
from orchestrator.core.targets import Target
from orchestrator.core.utils.json import json_dumps
from orchestrator.core.workflow import StepList, done, make_workflow, step
from pydantic_forms.core import FormPage
from pydantic_forms.exceptions import FormValidationError
from test.integration_tests.workflows import WorkflowInstanceForTests, assert_complete, extract_state, run_workflow

SECRET = "s3cr3t-e2e-password"  # noqa: S105 - test fixture, not a credential


class PageOneForm(FormPage):
    region: str


class PageTwoForm(FormPage):
    hostname: str = Field(min_length=4)
    password: SealedSecret


class PageThreeForm(FormPage):
    remark: str = ""


def _form_generator_two_pages(state):
    first = yield PageOneForm
    first_data = first.model_dump()  # attribute access: the pattern a raw-dict redaction walk breaks on
    second = yield PageTwoForm
    return second.model_dump() | {"region": first_data["region"]}


def _form_generator_three_pages(state):
    first = yield PageOneForm
    first_data = first.model_dump()
    second = yield PageTwoForm
    third = yield PageThreeForm
    return second.model_dump() | third.model_dump() | {"region": first_data["region"]}


@step("Seal and store")
def seal_step():
    return {}


def _make_workflow(form_generator):
    steps = StepList([seal_step]) >> done
    return make_workflow(lambda: None, "sealed secret e2e", form_generator, Target.SYSTEM, steps)


@pytest.fixture()
def sealed_keys(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [SecretStr(key)])
    return key


@pytest.mark.workflow
def test_envelope_stored_not_cleartext(sealed_keys):
    with WorkflowInstanceForTests(_make_workflow(_form_generator_two_pages), "sealed_e2e_two_pages"):
        result, process, _ = run_workflow(
            "sealed_e2e_two_pages", [{"region": "eu"}, {"hostname": "host-1", "password": SECRET}]
        )
        # Query inside the block: exiting it deletes the workflow row, cascading to process rows.
        input_states = db.session.scalars(
            select(InputStateTable.input_state).where(InputStateTable.process_id == process.process_id)
        ).all()

    assert_complete(result)
    state = extract_state(result)
    assert is_sealed_envelope(state["password"])
    assert SECRET not in state["password"]

    blob = json_dumps(input_states)
    assert "fernet-v1:" in blob
    assert SECRET not in blob


@pytest.mark.workflow
def test_validation_error_log_masks_multi_page_sealed_cleartext(sealed_keys, caplog):
    # Page two fails validation (short hostname) while carrying a cleartext secret. The walk must
    # advance past page one via validated data to learn page two's sealed fields.
    with WorkflowInstanceForTests(_make_workflow(_form_generator_two_pages), "sealed_e2e_mask"):
        with caplog.at_level(logging.INFO, logger="pydantic_forms"):
            with pytest.raises(FormValidationError):
                run_workflow("sealed_e2e_mask", [{"region": "eu"}, {"hostname": "ab", "password": SECRET}])

    assert "REDACTED" in caplog.text
    assert SECRET not in caplog.text


@pytest.mark.workflow
def test_validation_error_log_omits_when_later_page_unresolvable(sealed_keys, caplog):
    # Page two fails and a third page's input was submitted: page three's form class is unreachable
    # without passing page two's validation, so the values are omitted rather than risk a leak.
    with WorkflowInstanceForTests(_make_workflow(_form_generator_three_pages), "sealed_e2e_omit"):
        with caplog.at_level(logging.INFO, logger="pydantic_forms"):
            with pytest.raises(FormValidationError):
                run_workflow(
                    "sealed_e2e_omit",
                    [{"region": "eu"}, {"hostname": "ab", "password": SECRET}, {"remark": "x"}],
                )

    assert "omitted" in caplog.text
    assert SECRET not in caplog.text


@pytest.mark.workflow
def test_validation_error_log_masks_when_keys_disabled(monkeypatch, caplog):
    # Fail-closed: with no keys, page two's SealedSecret field itself fails validation. Sealed field
    # names come from the schema, not the keys, so the failing (last) page's cleartext is still masked.
    monkeypatch.setattr(app_settings, "SEALED_SECRETS_FERNET_KEYS", [])
    with WorkflowInstanceForTests(_make_workflow(_form_generator_two_pages), "sealed_e2e_disabled"):
        with caplog.at_level(logging.INFO, logger="pydantic_forms"):
            with pytest.raises(FormValidationError):
                run_workflow("sealed_e2e_disabled", [{"region": "eu"}, {"hostname": "host-1", "password": SECRET}])

    assert "REDACTED" in caplog.text
    assert SECRET not in caplog.text
