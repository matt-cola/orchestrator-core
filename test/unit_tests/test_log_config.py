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

"""Tests for logger level overrides.

Sealed-secret cleartext reaches the log pipeline when `pydantic_forms` logs raw `user_inputs` at
DEBUG, so that logger must default to INFO.
"""

from orchestrator.core.log_config import LOGGER_OVERRIDES, logger_config


def test_pydantic_forms_defaults_to_info():
    # pydantic_forms logs raw user_inputs at DEBUG (core/sync.py, core/asynchronous.py);
    # at global LOG_LEVEL=DEBUG that would leak sealed cleartext into the log pipeline.
    assert LOGGER_OVERRIDES["pydantic_forms"]["level"] == "INFO"


def test_pydantic_forms_override_is_env_controlled(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL_PYDANTIC_FORMS", "DEBUG")
    assert logger_config("pydantic_forms", default_level="INFO")[1]["level"] == "DEBUG"


def test_logger_config_propagates_to_root():
    name, config = logger_config("pydantic_forms", default_level="INFO")
    assert name == "pydantic_forms"
    assert config["propagate"] is True
