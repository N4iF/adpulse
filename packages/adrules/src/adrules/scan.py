"""ScanResult, the lifecycle diff between two scans, and scan storage (docs/architecture.md)."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from adrules.finding import CheckResult, Finding, Status
from adsnap.model import CoverageLevel, Snapshot

SCHEMA_VERSION = "1.0"


class LifecycleEntry(BaseModel):
    key: str
    state: Literal["new", "open", "resolved"]
    not_reassessed: bool = False
    finding: Finding


class ScanResult(BaseModel):
    schema_version: str = SCHEMA_VERSION
    snapshot_id: str
    collected_at: datetime
    domain: str
    mode: str
    coverage: dict[str, CoverageLevel]
    results: list[CheckResult]
    lifecycle: list[LifecycleEntry] = Field(default_factory=list)
    previous_scan_id: str | None = None

    def count(self, state: str) -> int:
        return sum(1 for e in self.lifecycle if e.state == state)

    def failed(self) -> int:
        return sum(1 for r in self.results if r.status is Status.FAIL)

    def assessed(self) -> int:
        return sum(1 for r in self.results if r.status in (Status.PASS, Status.FAIL))


def finding_key(f: Finding) -> str:
    return "|".join([f.rule_id, f.affected_object, f.subject_id or ""])


def diff(previous: ScanResult | None, results: list[CheckResult]) -> list[LifecycleEntry]:
    current = {finding_key(f): f for r in results for f in r.findings}
    # Start from what was still open after the previous scan (including findings it could not re-assess),
    # so the "not re-assessed" guard holds for as many scans as the rule cannot run.
    before = {e.key: e.finding for e in (previous.lifecycle if previous else []) if e.state in ("new", "open")}
    reassessed = {r.rule_id for r in results if r.status in (Status.PASS, Status.FAIL)}
    out = [LifecycleEntry(key=k, state="open" if k in before else "new", finding=f) for k, f in current.items()]
    for k, f in before.items():
        if k in current:
            continue
        if f.rule_id in reassessed:
            out.append(LifecycleEntry(key=k, state="resolved", finding=f))
        else:  # the rule could not run this time: never claim "resolved"
            out.append(LifecycleEntry(key=k, state="open", not_reassessed=True, finding=f))
    return out


def build_scan(snapshot: Snapshot, results: list[CheckResult], previous: ScanResult | None) -> ScanResult:
    meta = snapshot.snapshot
    return ScanResult(
        snapshot_id=meta.id, collected_at=meta.collected_at, domain=snapshot.domain().name, mode=meta.collector.mode,
        coverage=snapshot.coverage, results=results, lifecycle=diff(previous, results),
        previous_scan_id=previous.snapshot_id if previous else None,
    )


def previous_scan(history: list[ScanResult], snapshot: Snapshot) -> ScanResult | None:
    """The latest saved scan of the same domain collected before this snapshot."""
    meta = snapshot.snapshot
    earlier = [
        s for s in history
        if s.domain == snapshot.domain().name and s.collected_at < meta.collected_at and s.snapshot_id != meta.id
    ]
    return max(earlier, key=lambda s: s.collected_at, default=None)


def load_scans(folder: Path) -> list[ScanResult]:
    if not folder.exists():
        return []
    scans = [ScanResult.model_validate_json(p.read_text(encoding="utf-8")) for p in folder.glob("*.scan.json")]
    return sorted(scans, key=lambda s: s.collected_at)


def save_scan(scan: ScanResult, folder: Path) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{scan.snapshot_id}.scan.json"
    if path.exists():
        raise FileExistsError(f"scan {scan.snapshot_id} already exists in {folder}")
    path.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return path
