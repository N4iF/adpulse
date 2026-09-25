from pathlib import Path

import pytest
import yaml

from adrules.catalog import load_catalog, run_all
from adrules.finding import Status
from adsnap.model import CoverageLevel, ObjectType, Snapshot

FIX = Path(__file__).parent / "fixtures"
TRUTH = yaml.safe_load((Path(__file__).resolve().parents[3] / "lab" / "expected-findings.yaml").read_text(encoding="utf-8"))
IMPLEMENTED = sorted(r.meta.id for r in load_catalog())


def _recorded_by_an_older_collector(snap: Snapshot) -> bool:
    """A clean recording that lacks what the current collector reads (computers, the machine account quota).

    A recording with collection errors never counts as older: the test then fails, so a real failure shows.
    """
    clean = snap.coverage_of("directory_objects") is CoverageLevel.FULL and not snap.errors
    lacks = not snap.by_type(ObjectType.COMPUTER) or snap.domain().derived.get("machine_account_quota") is None
    return clean and lacks


@pytest.mark.parametrize("state", sorted(TRUTH["fixtures"]))
def test_lab_matches_ground_truth(state: str) -> None:
    path = FIX / TRUTH["fixtures"][state]
    if not path.exists():
        pytest.skip(f"record {path.name} on DC1 first (lab steps of the current increment plan)")
    snap = Snapshot.model_validate_json(path.read_text(encoding="utf-8"))
    if _recorded_by_an_older_collector(snap):
        pytest.skip(f"{path.name} was recorded by an older collector; re-record it on DC1")
    results = run_all(snap)
    assert all(r.status in (Status.PASS, Status.FAIL) for r in results), "every check must be assessed on the lab"
    flagged = {r.rule_id: sorted(f.affected_name for f in r.findings) for r in results}
    expected = {rule_id: sorted(TRUTH["states"][state].get(rule_id, [])) for rule_id in IMPLEMENTED}
    assert flagged == expected


def test_ground_truth_names_only_known_states() -> None:
    assert set(TRUTH["states"]) == set(TRUTH["fixtures"])
