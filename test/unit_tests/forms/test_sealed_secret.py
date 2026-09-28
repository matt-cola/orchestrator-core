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
from pydantic import BaseModel, Field

from orchestrator.core.forms.validators.sealed_secret import (
    SEALED_REDACTED,
    is_sealed_envelope,
    is_sealed_secret_annotation,
    mask_sealed_cleartext,
    redacted_user_inputs,
    sealed_field_names,
)
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
