"""Tests for target type detection and CIDR safety limits in tools/hunt.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def load_hunt_module():
    hunt_path = Path(__file__).resolve().parents[1] / "tools" / "hunt.py"
    spec = importlib.util.spec_from_file_location("hunt_module", hunt_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_detect_target_type_domain():
    hunt = load_hunt_module()
    assert hunt.detect_target_type("example.com") == "domain"


def test_detect_target_type_ip():
    hunt = load_hunt_module()
    assert hunt.detect_target_type("192.0.2.10") == "ip"


def test_detect_target_type_cidr():
    hunt = load_hunt_module()
    assert hunt.detect_target_type("192.0.2.0/24") == "cidr"


def test_expand_cidr_small_range():
    hunt = load_hunt_module()
    assert hunt.expand_cidr("192.0.2.0/30") == ["192.0.2.1", "192.0.2.2"]


def test_expand_cidr_rejects_large_ranges():
    hunt = load_hunt_module()
    try:
        hunt.expand_cidr("192.0.2.0/23")
    except ValueError as exc:
        assert "supported limit" in str(exc)
    else:
        raise AssertionError("expected oversized CIDR to be rejected")


def test_run_recon_rejects_large_cidr_before_spawning(monkeypatch):
    hunt = load_hunt_module()

    popen_called = False

    def fake_popen(*args, **kwargs):
        nonlocal popen_called
        popen_called = True
        raise AssertionError("subprocess should not be started for oversized CIDR")

    monkeypatch.setattr(hunt.subprocess, "Popen", fake_popen)

    assert hunt.run_recon("192.0.2.0/23") is False
    assert popen_called is False


def test_recon_engine_expands_cidr_when_nmap_is_unavailable():
    recon_engine = (Path(__file__).resolve().parents[1] / "tools" / "recon_engine.sh").read_text()

    assert "_expand_cidr_hosts" in recon_engine
    assert 'log_warn "nmap not installed — expanding the CIDR locally for downstream probing"' in recon_engine
    assert 'log_warn "nmap did not identify live hosts — expanding the CIDR locally for downstream probing"' in recon_engine
