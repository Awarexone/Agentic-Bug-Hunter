"""Tests for the LiteLLM provider in brain.LLMClient.

LiteLLM is an optional gateway backend: one call shape reaches 100+ providers,
routed by the "provider/model" prefix using each provider's own credential env
var (or a LiteLLM proxy via LITELLM_API_KEY / LITELLM_API_BASE). These tests
stub the `litellm` module so the suite runs without the real dependency.
"""

import importlib
import os
import sys
import types

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)

_ENV = (
    "BRAIN_PROVIDER", "BRAIN_MODEL", "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
    "XAI_API_KEY", "GROQ_API_KEY", "DEEPSEEK_API_KEY", "GEMINI_API_KEY",
    "MOONSHOT_API_KEY", "MISTRAL_API_KEY", "TOGETHER_API_KEY",
    "CEREBRAS_API_KEY", "PERPLEXITY_API_KEY", "OPENROUTER_API_KEY",
    "ORCAROUTER_API_KEY", "LITELLM_API_KEY", "LITELLM_API_BASE",
    "LITELLM_BASE_URL",
)


def _install_litellm_stub(completion=None, valid_models=None):
    """Register a fake `litellm` module and return its completion mock."""
    fake = types.ModuleType("litellm")
    calls: list[dict] = []

    def _completion(**kwargs):
        calls.append(kwargs)
        if completion is not None:
            return completion(**kwargs)
        msg = types.SimpleNamespace(content="LITELLM_OK")
        return types.SimpleNamespace(choices=[types.SimpleNamespace(message=msg)])

    fake.completion = _completion
    fake.get_valid_models = lambda *a, **k: list(valid_models or [])
    fake._calls = calls
    sys.modules["litellm"] = fake
    return fake


@pytest.fixture
def brain_module(monkeypatch):
    for env in _ENV:
        monkeypatch.delenv(env, raising=False)
    import brain
    importlib.reload(brain)
    return brain


def test_litellm_registered_in_maps(brain_module):
    LLMClient = brain_module.LLMClient
    assert LLMClient.DEFAULT_MODELS["litellm"] == "gpt-4o"
    assert LLMClient.PROVIDER_KEY_ENV["litellm"] == "LITELLM_API_KEY"
    # must be the last key-env entry so auto-detect never preempts a
    # directly-configured provider
    assert list(LLMClient.PROVIDER_KEY_ENV)[-1] == "litellm"


def test_litellm_available_without_key(brain_module):
    """Explicit selection works with no LITELLM_API_KEY (per-provider fallback)."""
    _install_litellm_stub()
    client = brain_module.LLMClient(provider="litellm")
    assert client.available is True
    assert client._litellm_api_key == ""
    assert client._litellm_api_base == ""


def test_litellm_unavailable_when_not_installed(brain_module, monkeypatch):
    monkeypatch.setitem(sys.modules, "litellm", None)  # force ImportError
    client = brain_module.LLMClient(provider="litellm")
    assert client.available is False


def test_chat_dispatches_with_drop_params_and_omits_blank_creds(brain_module):
    fake = _install_litellm_stub()
    client = brain_module.LLMClient(provider="litellm")
    out = client.chat("anthropic/claude-sonnet-4-6", "sys", "hi", max_tokens=64, temperature=0.2)
    assert out == "LITELLM_OK"
    call = fake._calls[-1]
    assert call["model"] == "anthropic/claude-sonnet-4-6"
    assert call["drop_params"] is True
    assert call["max_tokens"] == 64 and call["temperature"] == 0.2
    assert call["messages"][0]["role"] == "system"
    # creds omitted when unset so litellm uses each provider's own env var
    assert "api_key" not in call and "api_base" not in call


def test_chat_forwards_proxy_creds_when_set(brain_module, monkeypatch):
    monkeypatch.setenv("LITELLM_API_KEY", "sk-proxy")
    monkeypatch.setenv("LITELLM_API_BASE", "http://localhost:4000/v1")
    fake = _install_litellm_stub()
    client = brain_module.LLMClient(provider="litellm")
    client.chat(None, "sys", "hi")
    call = fake._calls[-1]
    assert call["model"] == "gpt-4o"  # DEFAULT_MODELS fallback
    assert call["api_key"] == "sk-proxy"
    assert call["api_base"] == "http://localhost:4000/v1"


def test_auto_detect_only_picks_litellm_with_key(brain_module, monkeypatch):
    _install_litellm_stub()
    # no keys at all -> falls back to ollama, never litellm
    assert "litellm" not in brain_module.LLMClient.PROVIDER_PRIORITY
    monkeypatch.setenv("LITELLM_API_KEY", "sk-proxy")
    client = brain_module.LLMClient()
    assert client.provider == "litellm"
    assert client.available is True


def test_list_models_sdk_mode_uses_discovery(brain_module):
    _install_litellm_stub(valid_models=["gpt-4o", "anthropic/claude-sonnet-4-6"])
    client = brain_module.LLMClient(provider="litellm")
    assert client.list_models() == ["gpt-4o", "anthropic/claude-sonnet-4-6"]


def test_list_models_proxy_mode_queries_endpoint(brain_module, monkeypatch):
    monkeypatch.setenv("LITELLM_API_BASE", "http://localhost:4000/v1")
    _install_litellm_stub()

    captured = {}

    class _Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": [{"id": "gpt-4.1-mini"}, {"id": "gemini-2.5-flash"}]}

    def _get(url, headers=None, timeout=None):
        captured["url"] = url
        return _Resp()

    import requests
    monkeypatch.setattr(requests, "get", _get)
    client = brain_module.LLMClient(provider="litellm")
    models = client.list_models()
    assert models == ["gpt-4.1-mini", "gemini-2.5-flash"]
    assert captured["url"] == "http://localhost:4000/v1/models"
