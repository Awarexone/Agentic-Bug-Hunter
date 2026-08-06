"""Tests for LLMClient._auto_detect provider-priority reshuffling.

Users with only a cloud API key set (e.g. ANTHROPIC_API_KEY) should hit
the matching provider first. Without any key, the original ordering
(Ollama → Claude → OpenAI → Grok) still applies.
"""

import importlib
import os
import sys

import pytest

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, ROOT)


@pytest.fixture
def brain_module(monkeypatch):
    for env in (
        "BRAIN_PROVIDER", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "XAI_API_KEY",
        "OPENROUTER_API_KEY",
    ):
        monkeypatch.delenv(env, raising=False)
    import brain
    importlib.reload(brain)
    return brain


class _Tracker:
    """Records _init_provider calls; marks a chosen provider available."""

    def __init__(self, available_provider: str | None = None):
        self.calls: list[str] = []
        self.available_provider = available_provider

    def bind(self, client):
        def _init(provider: str) -> None:
            self.calls.append(provider)
            client.available = provider == self.available_provider
        client._init_provider = _init


def test_anthropic_key_jumps_to_front(brain_module, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="claude")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "claude"
    assert tracker.calls[0] == "claude", "claude must be probed first when its key is set"


def test_openai_and_grok_keys_both_front_nothing_available(brain_module, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("XAI_API_KEY", "xai-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider=None)
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "ollama"
    assert set(tracker.calls[:2]) == {"openai", "grok"}, \
        "key-bearing providers must be probed before the rest"
    rest = [p for p in brain_module.LLMClient.PROVIDER_PRIORITY
            if p not in ("openai", "grok")]
    assert tracker.calls[2:] == rest, \
        "providers without keys keep their original relative order"


def test_no_keys_falls_back_to_default_priority(brain_module):
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider=None)
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "ollama"
    assert tracker.calls == list(brain_module.LLMClient.PROVIDER_PRIORITY)


def test_key_set_but_provider_unavailable_falls_through(brain_module, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="ollama")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "ollama"
    assert tracker.calls[0] == "claude"
    assert "ollama" in tracker.calls


def test_openrouter_key_jumps_to_front(brain_module, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    tracker = _Tracker(available_provider="openrouter")
    tracker.bind(client)

    chosen = brain_module.LLMClient._auto_detect(client)

    assert chosen == "openrouter"
    assert tracker.calls[0] == "openrouter"


def test_openrouter_init_sets_api_base(brain_module, monkeypatch):
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-or-test")
    client = brain_module.LLMClient.__new__(brain_module.LLMClient)
    client.available = False
    client._ollama = None
    client._http = None
    client.description = ""
    client.provider = "openrouter"

    brain_module.LLMClient._init_provider(client, "openrouter")

    assert client.available is True
    assert client._api_base == "https://openrouter.ai/api/v1"
    assert "openrouter" in client.description.lower()
    assert brain_module.LLMClient.DEFAULT_MODELS["openrouter"] == "anthropic/claude-sonnet-4.6"
    assert "anthropic/claude-sonnet-4.6" in brain_module.LLMClient.list_models(client)
