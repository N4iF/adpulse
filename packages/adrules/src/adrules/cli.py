"""adrules: evaluate a snapshot, or run a full scan (collect → rules → diff → EN and AR HTML reports)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer

from adrules.catalog import run_all
from adrules.report import render_report
from adrules.scan import build_scan, load_scans, previous_scan, save_scan
from adsnap.model import Snapshot

app = typer.Typer(help="ADPulse rules engine", no_args_is_help=True)


def _utf8_output() -> None:
    """Arabic text must print whatever the console code page is (Windows PowerShell 5.1 uses cp1252)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(encoding="utf-8")


@app.command()
def evaluate(
    snapshot: Path = typer.Argument(..., exists=True, help="a snapshot JSON"),
    out: Path | None = typer.Option(None, "--out", help="write the JSON to this file (UTF-8, no BOM) instead of printing it"),
) -> None:
    """Print (or write) the check results for a saved snapshot as JSON."""
    _utf8_output()
    snap = Snapshot.model_validate_json(snapshot.read_text(encoding="utf-8"))
    text = json.dumps([r.model_dump(mode="json") for r in run_all(snap)], ensure_ascii=False, indent=2)
    if out is None:  # note: Windows PowerShell 5.1 adds a BOM when output is redirected with '>'; use --out
        typer.echo(text)
    else:
        out.write_text(text + "\n", encoding="utf-8")
        typer.echo(f"results -> {out}")


@app.command()
def scan(
    out_dir: Path = typer.Option(Path("snapshots"), "--out-dir", help="scan results and reports (git-ignored)"),
    from_snapshot: Path | None = typer.Option(None, "--from-snapshot", help="use a saved snapshot instead of collecting"),
    insecure_lab: bool = typer.Option(False, "--insecure-lab", help="skip TLS validation (lab only)"),
) -> None:
    """Collect (or load) a snapshot, run the checks, compare with the previous scan, write both reports."""
    _utf8_output()
    if from_snapshot:
        snap = Snapshot.model_validate_json(from_snapshot.read_text(encoding="utf-8"))
    else:
        from adsnap.cli import DirectoryReadError, collect_from_env

        try:
            snap = collect_from_env(insecure_lab)
        except DirectoryReadError as exc:
            typer.echo(f"error: {exc}", err=True)
            raise typer.Exit(1) from exc
    history = load_scans(out_dir)
    result = build_scan(snap, run_all(snap), previous_scan(history, snap))
    try:
        save_scan(result, out_dir)
    except FileExistsError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc
    shown = [s for s in history if s.domain == result.domain and s.collected_at < result.collected_at] + [result]
    reports = []
    for lang in ("en", "ar"):
        path = out_dir / f"{result.snapshot_id}.{lang}.html"
        path.write_text(render_report(result, shown, lang), encoding="utf-8")
        reports.append(path)
    typer.echo(
        f"{len(result.results)} checks: {result.failed()} failed | new {result.count('new')}, "
        f"open {result.count('open')}, resolved {result.count('resolved')}"
    )
    for path in reports:
        typer.echo(f"report: {path}")
