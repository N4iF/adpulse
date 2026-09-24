import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from typer.testing import CliRunner

from adrules.cli import app
from adsnap.testing import make_domain, make_snapshot

FRESH = dict(min_password_length=7, password_complexity=True, lockout_threshold=0)
FIXED = dict(min_password_length=14, password_complexity=True, lockout_threshold=5)


def _write(tmp_path: Path, name: str, domain: dict[str, Any], day: int) -> Path:
    p = tmp_path / name
    p.write_text(make_snapshot(make_domain(**domain), collected_at=datetime(2026, 10, day, tzinfo=UTC)).model_dump_json(), encoding="utf-8")
    return p


def test_scan_twice_from_snapshots_writes_both_languages(tmp_path: Path) -> None:
    out = tmp_path / "scans"
    r1 = CliRunner().invoke(app, ["scan", "--from-snapshot", str(_write(tmp_path, "d.json", FRESH, 1)), "--out-dir", str(out)])
    assert r1.exit_code == 0, r1.output
    assert "3 checks: 2 failed | new 2, open 0, resolved 0" in r1.output
    r2 = CliRunner().invoke(app, ["scan", "--from-snapshot", str(_write(tmp_path, "f.json", FIXED, 2)), "--out-dir", str(out)])
    assert r2.exit_code == 0, r2.output
    assert "3 checks: 0 failed | new 0, open 0, resolved 2" in r2.output
    assert len(list(out.glob("*.scan.json"))) == 2
    assert len(list(out.glob("*.en.html"))) == 2 and len(list(out.glob("*.ar.html"))) == 2


def test_same_snapshot_twice_is_refused(tmp_path: Path) -> None:
    out, snap = tmp_path / "scans", _write(tmp_path, "d.json", FRESH, 1)
    assert CliRunner().invoke(app, ["scan", "--from-snapshot", str(snap), "--out-dir", str(out)]).exit_code == 0
    again = CliRunner().invoke(app, ["scan", "--from-snapshot", str(snap), "--out-dir", str(out)])
    assert again.exit_code != 0 and "already" in again.output


def test_evaluate_writes_utf8_json_without_bom(tmp_path: Path) -> None:
    out = tmp_path / "results.json"
    r = CliRunner().invoke(app, ["evaluate", str(_write(tmp_path, "d.json", FRESH, 1)), "--out", str(out)])
    assert r.exit_code == 0, r.output
    data = out.read_bytes()
    assert not data.startswith(b"\xef\xbb\xbf")
    assert json.loads(data.decode("utf-8"))[0]["rule_id"] == "PWD-01"


def test_evaluate_prints_json_with_arabic(tmp_path: Path) -> None:
    r = CliRunner().invoke(app, ["evaluate", str(_write(tmp_path, "d.json", FRESH, 1))])
    assert r.exit_code == 0, r.output
    assert '"rule_id": "PWD-01"' in r.output and "قصير جداً" in r.output
