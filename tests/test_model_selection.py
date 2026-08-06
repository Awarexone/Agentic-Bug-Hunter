"""Tests for explicit provider model selection."""

import json
from types import SimpleNamespace

import engine
import brain


def test_configured_model_uses_saved_provider_choice(monkeypatch):
    monkeypatch.delenv("BRAIN_MODEL", raising=False)
    cfg = {"provider": "ollama", "models": {"ollama": "qwen3:14b"}}

    assert engine._configured_model(cfg, "ollama") == "qwen3:14b"


def test_environment_model_overrides_saved_choice(monkeypatch):
    monkeypatch.setenv("BRAIN_MODEL", "qwen3:8b")
    cfg = {"models": {"ollama": "qwen3:14b"}}

    assert engine._configured_model(cfg, "ollama") == "qwen3:8b"


def test_provider_model_choices_are_isolated(monkeypatch):
    monkeypatch.delenv("BRAIN_MODEL", raising=False)
    cfg = {"models": {"ollama": "qwen3:14b", "groq": "custom-groq"}}

    assert engine._configured_model(cfg, "ollama") == "qwen3:14b"
    assert engine._configured_model(cfg, "groq") == "custom-groq"


def test_explicit_missing_ollama_model_does_not_fall_back(monkeypatch):
    monkeypatch.setattr(brain, "_get_available_models", lambda: ["qwen3:8b"])

    assert brain._pick_model("missing:latest") is None


def test_automatic_ollama_model_still_uses_priority(monkeypatch):
    monkeypatch.setattr(
        brain,
        "_get_available_models",
        lambda: ["random:latest", "qwen3:8b"],
    )

    assert brain._pick_model() == "qwen3:8b"


def test_setup_persists_explicit_ollama_provider_and_model(monkeypatch, tmp_path):
    class FakeClient:
        available = True
        description = "fake Ollama"

        def __init__(self, provider, model=None):
            assert provider == "ollama"

        def list_models(self):
            return ["qwen3:8b", "qwen2.5:14b"]

        def chat(self, model, *args, **kwargs):
            assert model == "qwen2.5:14b"
            return "READY"

    config_path = tmp_path / "config.json"
    monkeypatch.setattr(engine, "CONFIG", config_path)
    monkeypatch.setattr(engine, "_import_brain", lambda: (object, FakeClient))
    monkeypatch.delenv("BRAIN_MODEL", raising=False)

    engine.cmd_setup(SimpleNamespace(
        setup_provider="ollama",
        setup_model="qwen2.5:14b",
        provider=None,
        model=None,
    ))

    assert json.loads(config_path.read_text()) == {
        "provider": "ollama",
        "models": {"ollama": "qwen2.5:14b"},
    }
