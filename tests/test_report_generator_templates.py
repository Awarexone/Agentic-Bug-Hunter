"""Regression tests for legacy report coverage in tools/report_generator.py."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def load_report_generator():
    report_path = Path(__file__).resolve().parents[1] / "tools" / "report_generator.py"
    spec = importlib.util.spec_from_file_location("report_generator_module", report_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_legacy_templates_and_mappings_are_preserved():
    report_generator = load_report_generator()

    for key in ("redirect", "auth_bypass", "info_disclosure", "cve", "cves"):
        assert key in report_generator.VULN_TEMPLATES

    assert report_generator.SUBDIR_VTYPE["redirects"] == "redirect"
    assert report_generator.SUBDIR_VTYPE["auth_bypass"] == "auth_bypass"
    assert report_generator.SUBDIR_VTYPE["cves"] == "cve"


def test_nested_sessions_still_resolve_to_top_level_reports_dir():
    report_generator = load_report_generator()
    target, session, report_dir = report_generator.resolve_target_and_report_dir(
        "/tmp/findings/acme.example/sessions/20260403_120000"
    )

    assert target == "acme.example"
    assert session == "20260403_120000"
    assert Path(report_dir).parts[-4:] == ("reports", "acme.example", "sessions", "20260403_120000")


def test_process_findings_dir_renders_legacy_finding_types(tmp_path, monkeypatch):
    report_generator = load_report_generator()
    findings_dir = tmp_path / "acme.example" / "sessions" / "20260403_120000"
    (findings_dir / "redirects").mkdir(parents=True)
    (findings_dir / "auth_bypass").mkdir()
    (findings_dir / "cves").mkdir()
    (findings_dir / "misconfig").mkdir()

    (findings_dir / "redirects" / "findings.txt").write_text("https://acme.example/login?next=https://evil.example\n")
    (findings_dir / "auth_bypass" / "findings.txt").write_text("https://acme.example/admin\n")
    (findings_dir / "cves" / "findings.txt").write_text("CVE-2026-9999 https://acme.example/\n")
    (findings_dir / "misconfig" / "findings.txt").write_text("[info_disclosure] https://acme.example/config.js\n")

    monkeypatch.setenv("REPORTS_OUT_DIR", str(tmp_path / "reports"))

    count, findings, report_dir, html, md = report_generator.process_findings_dir(str(findings_dir))

    assert count == 4
    severity_by_vtype = {finding["vtype"]: finding["severity"] for finding in findings}
    assert severity_by_vtype["auth_bypass"] == "critical"
    assert severity_by_vtype["redirect"] == "low"
    assert severity_by_vtype["cve"] == "critical"

    assert "Open Redirect on acme.example" in html
    assert "Authentication/Authorization Bypass on acme.example" in html
    assert "Known CVE Vulnerability on acme.example" in html
    assert "Information Disclosure on acme.example" in md
    assert report_dir == str(tmp_path / "reports")


def test_manual_report_workflow_is_preserved(tmp_path, monkeypatch):
    report_generator = load_report_generator()
    monkeypatch.setattr(report_generator, "REPORTS_DIR", str(tmp_path / "reports"))

    report_dir, md_path, html_path = report_generator.create_manual_report(
        "xss",
        "https://acme.example/search?q=test",
        param="q",
        evidence="Confirmed reflected payload",
    )

    assert Path(report_dir).exists()
    assert Path(md_path).exists()
    assert Path(html_path).exists()
    assert "Confirmed reflected payload" in Path(md_path).read_text()

    poc_image = tmp_path / "poc.png"
    poc_image.write_bytes(b"fake-png")
    report_generator.attach_poc_images(md_path, [str(poc_image)])

    md = Path(md_path).read_text()
    assert "PoC Screenshots" in md
    assert "poc_screenshots/poc.png" in md
