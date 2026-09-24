from pathlib import Path

import pytest
import yaml

from adrules.catalog import run_all
from adrules.finding import Status
from adsnap.model import Snapshot

FIX = Path(__file__).parent / "fixtures"
TRUTH = yaml.safe_load((Path(__file__).resolve().parents[3] / "lab" / "expected-findings.yaml").read_text(encoding="utf-8"))["mvp1"]


@pytest.mark.parametrize(("fixture", "expected"), [("lab-default.json", "default_domain"), ("lab-fixed.json", "after_fix")])
def test_lab_matches_ground_truth(fixture: str, expected: str) -> None:
    path = FIX / fixture
    if not path.exists():
        pytest.skip(f"record {fixture} on DC1 first (Task 8)")
    snap = Snapshot.model_validate_json(path.read_text(encoding="utf-8"))
    results = run_all(snap)
    assert all(r.status in (Status.PASS, Status.FAIL) for r in results), "every check must be assessed on the lab"
    failed = sorted(r.rule_id for r in results if r.status is Status.FAIL)
    assert failed == sorted(TRUTH[expected])
