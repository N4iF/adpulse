import os
from pathlib import Path

import pytest
from typer.testing import CliRunner

from adsnap import cli
from adsnap.ldap import read_ca
from adsnap.testing import make_snapshot

KEYS = ("ADPULSE_DC", "ADPULSE_DOMAIN", "ADPULSE_USER", "ADPULSE_PASSWORD", "ADPULSE_MODE", "ADPULSE_CA_CERT")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in KEYS:
        monkeypatch.delenv(key, raising=False)


def test_collect_is_a_subcommand(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    assert CliRunner().invoke(cli.app, ["collect", "--help"]).exit_code == 0
    monkeypatch.setattr(cli, "collect_from_env", lambda insecure_lab: make_snapshot())
    out = tmp_path / "snap.json"
    result = CliRunner().invoke(cli.app, ["collect", "--out", str(out)])
    assert result.exit_code == 0, result.output
    assert out.exists() and "-> " in result.output


def test_dotenv_values(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_bytes(
        "﻿# lab settings\n"
        "ADPULSE_DC=dc1.corp.local          # DNS name, not IP\n"
        "ADPULSE_DOMAIN = corp.local\n"
        'ADPULSE_USER="adpulse.reader@corp.local"\n'
        "ADPULSE_PASSWORD=Ab3#x!Q-9\n".encode()
    )
    cli.load_dotenv(env)
    assert os.environ["ADPULSE_DC"] == "dc1.corp.local"
    assert os.environ["ADPULSE_DOMAIN"] == "corp.local"
    assert os.environ["ADPULSE_USER"] == "adpulse.reader@corp.local"
    assert os.environ["ADPULSE_PASSWORD"] == "Ab3#x!Q-9"  # noqa: S105 - synthetic test value


def test_environment_wins_over_dotenv(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    env = tmp_path / ".env"
    env.write_text("ADPULSE_DC=dc1.corp.local\n", encoding="utf-8")
    monkeypatch.setenv("ADPULSE_DC", "other.corp.local")
    cli.load_dotenv(env)
    assert os.environ["ADPULSE_DC"] == "other.corp.local"


def test_utf16_dotenv_is_rejected_clearly(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_text("ADPULSE_DC=dc1.corp.local\n", encoding="utf-16")
    with pytest.raises(ValueError, match="UTF-8"):
        cli.load_dotenv(env)


def test_utf16_without_bom_is_rejected_clearly(tmp_path: Path) -> None:
    env = tmp_path / ".env"
    env.write_bytes("ADPULSE_DC=dc1.corp.local\n".encode("utf-16-le"))
    with pytest.raises(ValueError, match="UTF-8"):
        cli.load_dotenv(env)


def test_bad_dotenv_is_a_clean_cli_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / ".env").write_text("ADPULSE_DC=dc1.corp.local\n", encoding="utf-16")
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(cli.app, ["collect", "--out", "x.json"])
    assert result.exit_code == 2 and "UTF-8" in result.output


def test_missing_settings_are_named() -> None:
    with pytest.raises(Exception, match="ADPULSE_DC"):
        cli.collect_from_env(False, dotenv=Path("does-not-exist.env"))


def test_ca_file_pem_or_der(tmp_path: Path) -> None:
    pem = tmp_path / "ca.pem"
    pem.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", encoding="ascii")
    der = tmp_path / "ca.cer"
    der.write_bytes(b"\x30\x82\x01\x0a\x02")
    assert isinstance(read_ca(str(pem)), str)
    assert read_ca(str(der)) == b"\x30\x82\x01\x0a\x02"
    bom_pem = tmp_path / "bom.pem"  # Windows PowerShell 5.1 writes UTF-8 with a BOM by default
    bom_pem.write_bytes(b"\xef\xbb\xbf-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    assert read_ca(str(bom_pem)) == "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
