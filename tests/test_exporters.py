import json

from core.models import Severity
from reports.exporter import to_json
from reports.pdf_exporter import to_pdf
from tests.conftest import make_finding, make_report


def test_to_json_schema_and_values():
    data = json.loads(to_json(make_report()))

    assert set(data) == {"meta", "target", "summary", "findings", "assets", "errors"}
    assert data["meta"]["tool"] == "prowl"
    assert data["meta"]["version"] == "0.1.0"
    assert data["target"]["domain"] == "example.com"

    s = data["summary"]
    assert s["total_findings"] == len(data["findings"]) == 2
    assert s["by_severity"] == {"critical": 0, "high": 0, "medium": 1, "low": 0, "info": 1}
    assert isinstance(s["duration_seconds"], float)

    first = data["findings"][0]
    assert first["id"] == "F001" and first["severity"] == "medium"
    assert first["timestamp"].endswith("+00:00")   # timezone-aware, ms precision


def test_to_json_writes_file(tmp_path):
    out = tmp_path / "r.json"
    text = to_json(make_report(), str(out))
    assert out.read_text(encoding="utf-8") == text


def test_to_json_keeps_unicode(tmp_path):
    f = make_finding(Severity.INFO, title="Dépôts des comptes — société")
    text = to_json(make_report([f]))
    assert "Dépôts des comptes — société" in text


def test_to_pdf_writes_valid_pdf(tmp_path):
    out = tmp_path / "r.pdf"
    to_pdf(make_report(errors={"crt.sh": "RuntimeError: down"}), str(out))
    blob = out.read_bytes()
    assert blob.startswith(b"%PDF")
    assert len(blob) > 5_000


def test_to_pdf_handles_empty_report(tmp_path):
    out = tmp_path / "empty.pdf"
    to_pdf(make_report([], assets={"subdomains": [], "emails": [], "ips": []}), str(out))
    assert out.read_bytes().startswith(b"%PDF")
