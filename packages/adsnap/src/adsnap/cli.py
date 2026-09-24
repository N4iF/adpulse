"""adsnap: collect a snapshot (connection settings from the environment or .env in the current folder)."""

from __future__ import annotations

import os
import re
from pathlib import Path

import typer

from adsnap.model import Snapshot

app = typer.Typer(help="ADPulse snapshot collector", no_args_is_help=True)

REQUIRED = ("ADPULSE_DC", "ADPULSE_DOMAIN", "ADPULSE_USER", "ADPULSE_PASSWORD")


class DirectoryReadError(RuntimeError):
    """The directory could not be read (connection, TLS, bind or search); no snapshot is produced."""


@app.callback()
def main() -> None:
    """ADPulse snapshot collector. Settings: docs/SETUP.md section 5."""


def _value(text: str) -> str:
    text = text.strip()
    if text[:1] in ("'", '"'):
        end = text.find(text[0], 1)
        if end != -1:
            return text[1:end]
    return re.split(r"\s+#", text, maxsplit=1)[0].strip()  # "#" after whitespace starts a comment


def load_dotenv(path: Path = Path(".env")) -> None:
    """Read KEY=VALUE lines. Variables already set in the environment win."""
    if not path.exists():
        return
    data = path.read_bytes()
    if data[:2] in (b"\xff\xfe", b"\xfe\xff") or b"\x00" in data:  # UTF-16, with or without a BOM
        raise ValueError(f"{path} is saved as UTF-16; save it as UTF-8")
    for line in data.decode("utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), _value(value))


def collect_from_env(insecure_lab: bool = False, *, dotenv: Path = Path(".env")) -> Snapshot:
    from ldap3.core.exceptions import LDAPException

    from adsnap import collector
    from adsnap.ldap import Ldap3DomainSource

    try:
        load_dotenv(dotenv)
    except ValueError as exc:
        raise typer.BadParameter(str(exc)) from exc
    env = os.environ
    missing = [k for k in REQUIRED if not env.get(k)]
    if missing:
        raise typer.BadParameter(f"set {', '.join(missing)} in .env (see docs/SETUP.md)")
    mode = env.get("ADPULSE_MODE", "standard")
    if mode not in ("standard", "privileged"):
        raise typer.BadParameter("ADPULSE_MODE must be standard or privileged")
    try:
        source = Ldap3DomainSource(
            env["ADPULSE_DC"], env["ADPULSE_USER"], env["ADPULSE_PASSWORD"],
            ca_cert=env.get("ADPULSE_CA_CERT") or None, insecure_lab=insecure_lab,
        )
        return collector.collect(source, domain_dns=env["ADPULSE_DOMAIN"], mode="privileged" if mode == "privileged" else "standard")
    except (LDAPException, OSError, LookupError, ValueError) as exc:  # ValueError: an unreadable CA file
        raise DirectoryReadError(f"could not read {env['ADPULSE_DC']} over LDAPS: {exc}") from exc


@app.command()
def collect(
    out: Path = typer.Option(..., "--out", help="where to write the snapshot JSON"),
    insecure_lab: bool = typer.Option(False, "--insecure-lab", help="skip TLS validation (lab only)"),
) -> None:
    """Read the domain as a standard user and write a snapshot JSON."""
    try:
        snap = collect_from_env(insecure_lab)
    except DirectoryReadError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(snap.model_dump_json(indent=2), encoding="utf-8")
    for error in snap.errors:
        typer.echo(f"warning: {error.stage}: {error.msg}", err=True)
    typer.echo(f"snapshot {snap.snapshot.id} -> {out}")
