"""NCA ECC-2:2024 technical-evidence view for subdomain 2-2 (D13, D36). Technical evidence only, never compliance.

The view is derived from a scan's check results and the rule catalog's `control_mappings`; nothing is collected
or stored for it.
"""

from __future__ import annotations

from collections import defaultdict
from importlib.resources import files
from typing import Literal

import yaml
from pydantic import BaseModel, Field

from adrules.catalog import Rule, load_catalog
from adrules.finding import CheckResult, Localized, Status

FRAMEWORK = "nca_ecc_2_2024"

EvidenceStatus = Literal["technical_evidence_pass", "technical_evidence_fail", "not_assessed"]

NO_CHECK_YET = Localized(
    en="No ADPulse check covers this control yet.",
    ar="لا يغطي أي فحص في ADPulse هذا الضابط حتى الآن.",
)
COULD_NOT_RUN = Localized(
    en="The checks for this control could not run in this scan.",
    ar="تعذّر تشغيل فحوصات هذا الضابط في عملية الفحص هذه.",
)


class ControlText(BaseModel):
    id: str
    text: Localized
    planned: list[str] = Field(default_factory=list)
    reason: Localized | None = None


class Subdomain(BaseModel):
    id: str
    title: Localized


class CheckRef(BaseModel):
    rule_id: str
    status: Status


class ControlEvidence(BaseModel):
    control_id: str
    text: Localized
    status: EvidenceStatus
    checks: list[CheckRef] = Field(default_factory=list)
    failing: list[str] = Field(default_factory=list)
    reason: Localized | None = None
    planned: list[str] = Field(default_factory=list)


class EccFile(BaseModel):
    subdomain: Subdomain
    controls: list[ControlText]


def _data() -> EccFile:
    return EccFile.model_validate(yaml.safe_load(files("adrules").joinpath("ecc_2_2024.yaml").read_text(encoding="utf-8")))


def load_subdomain() -> Subdomain:
    return _data().subdomain


def load_controls() -> dict[str, ControlText]:
    """The controls of subdomain 2-2-3, in document order."""
    return {c.id: c for c in _data().controls}


def _partial(missing: int, total: int) -> Localized:
    return Localized(
        en=f"{missing} of {total} checks could not run in this scan.",
        ar=f"تعذّر تشغيل {missing} من {total} فحوصات في عملية الفحص هذه.",
    )


def ecc_view(results: list[CheckResult], rules: list[Rule] | None = None) -> list[ControlEvidence]:
    """Per control: fail if a mapped check failed; pass if at least one ran and none failed; else not assessed."""
    rules = rules if rules is not None else load_catalog()
    mapped: dict[str, list[str]] = defaultdict(list)
    for rule in rules:
        for mapped_control in rule.meta.control_mappings.get(FRAMEWORK, []):
            mapped[mapped_control].append(rule.meta.id)
    implemented = {rule.meta.id for rule in rules}
    by_rule = {r.rule_id: r for r in results}

    view: list[ControlEvidence] = []
    for control_id, control in load_controls().items():
        mapped_ids = sorted(set(mapped.get(control_id, [])))  # a check counts once, even if listed twice
        checks = [CheckRef(rule_id=rid, status=by_rule[rid].status) for rid in mapped_ids if rid in by_rule]
        failing = [c.rule_id for c in checks if c.status is Status.FAIL]
        assessed = [c for c in checks if c.status in (Status.PASS, Status.FAIL)]
        planned = [p for p in control.planned if p not in implemented]
        status: EvidenceStatus
        reason: Localized | None = None
        if assessed:
            status = "technical_evidence_fail" if failing else "technical_evidence_pass"
            if len(assessed) < len(mapped_ids):  # a mapped check without a result also could not run
                reason = _partial(len(mapped_ids) - len(assessed), len(mapped_ids))
        else:
            status = "not_assessed"
            reason = control.reason or (COULD_NOT_RUN if mapped_ids else NO_CHECK_YET)
        view.append(ControlEvidence(
            control_id=control_id, text=control.text, status=status, checks=checks,
            failing=failing, reason=reason, planned=planned,
        ))
    return view


def summary(view: list[ControlEvidence]) -> dict[str, int]:
    counts = {"technical_evidence_fail": 0, "technical_evidence_pass": 0, "not_assessed": 0}
    for control in view:
        counts[control.status] += 1
    return counts
