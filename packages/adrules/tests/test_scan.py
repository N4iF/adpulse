from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from adrules.catalog import run_all
from adrules.scan import ScanResult, build_scan, load_scans, previous_scan, save_scan
from adsnap.model import CoverageLevel
from adsnap.testing import make_domain, make_snapshot

WEAK = dict(min_password_length=6, password_complexity=False, lockout_threshold=0)
FIXED = dict(min_password_length=14, password_complexity=True, lockout_threshold=5)
FRESH = dict(min_password_length=7, password_complexity=True, lockout_threshold=0)


def _scan(domain: dict[str, Any], previous: ScanResult | None = None, day: int = 1,
          coverage: dict[str, CoverageLevel] | None = None) -> ScanResult:
    snap = make_snapshot(make_domain(**domain), collected_at=datetime(2026, 10, day, tzinfo=UTC), coverage=coverage)
    return build_scan(snap, run_all(snap), previous)


def states(scan: ScanResult) -> list[tuple[str, str, bool]]:
    return sorted((e.finding.rule_id, e.state, e.not_reassessed) for e in scan.lifecycle)


def test_first_scan_everything_new() -> None:
    s1 = _scan(WEAK)
    assert states(s1) == [("PWD-01", "new", False), ("PWD-02", "new", False), ("PWD-04", "new", False)]
    assert s1.previous_scan_id is None


def test_fresh_domain_then_fix_resolves_two() -> None:
    s1 = _scan(FRESH)
    assert states(s1) == [("PWD-01", "new", False), ("PWD-04", "new", False)]
    s2 = _scan(FIXED, previous=s1, day=2)
    assert states(s2) == [("PWD-01", "resolved", False), ("PWD-04", "resolved", False)]
    assert s2.previous_scan_id == s1.snapshot_id
    assert s2.failed() == 0 and s2.count("resolved") == 2


def test_unchanged_is_open() -> None:
    s1 = _scan(WEAK)
    s2 = _scan(WEAK, previous=s1, day=2)
    assert {e.state for e in s2.lifecycle} == {"open"}


def test_resolved_is_not_carried_into_the_next_scan() -> None:
    s1 = _scan(WEAK)
    s2 = _scan(FIXED, previous=s1, day=2)
    s3 = _scan(FIXED, previous=s2, day=3)
    assert s3.lifecycle == []


def test_failed_collection_never_shows_false_resolved() -> None:
    s1 = _scan(WEAK)
    s2 = _scan(FIXED, previous=s1, day=2, coverage={"directory_objects": CoverageLevel.NONE})
    assert states(s2) == [("PWD-01", "open", True), ("PWD-02", "open", True), ("PWD-04", "open", True)]


def test_guard_holds_across_several_failed_scans() -> None:
    s1 = _scan(WEAK)
    s2 = _scan(WEAK, previous=s1, day=2, coverage={"directory_objects": CoverageLevel.NONE})
    s3 = _scan(WEAK, previous=s2, day=3, coverage={"directory_objects": CoverageLevel.NONE})
    assert {(e.state, e.not_reassessed) for e in s3.lifecycle} == {("open", True)}
    s4 = _scan(FIXED, previous=s3, day=4)
    assert states(s4) == [("PWD-01", "resolved", False), ("PWD-02", "resolved", False), ("PWD-04", "resolved", False)]
    s4b = _scan(WEAK, previous=s3, day=4)
    assert {(e.state, e.not_reassessed) for e in s4b.lifecycle} == {("open", False)}


def test_previous_scan_is_latest_earlier_scan_of_the_same_domain(tmp_path: Path) -> None:
    s1, s2 = _scan(WEAK, day=1), _scan(WEAK, day=3)
    other = _scan(WEAK, day=2).model_copy(update={"domain": "other.local"})
    for s in (s1, s2, other):
        save_scan(s, tmp_path)
    history = load_scans(tmp_path)
    snap_day2 = make_snapshot(make_domain(**WEAK), collected_at=datetime(2026, 10, 2, tzinfo=UTC))
    snap_day4 = make_snapshot(make_domain(**WEAK), collected_at=datetime(2026, 10, 4, tzinfo=UTC))
    assert previous_scan(history, snap_day2) == s1
    assert previous_scan(history, snap_day4) == s2


def test_saving_the_same_snapshot_twice_is_refused(tmp_path: Path) -> None:
    s1 = _scan(WEAK)
    save_scan(s1, tmp_path)
    with pytest.raises(FileExistsError):
        save_scan(s1, tmp_path)
