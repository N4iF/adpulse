"""Rule catalog: YAML metadata + Python evaluate(); coverage and privilege gates; runner (D31, D35)."""

from __future__ import annotations

import importlib
import importlib.resources
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from adrules.finding import CheckResult, Confidence, Finding, Localized, Severity, Status
from adsnap.model import COVERAGE_KEYS, ADObject, CoverageLevel, ObjectType, Snapshot


class NotAssessed(Exception):  # noqa: N818 - reads as a result, like Status.NOT_ASSESSED
    """Raised by a rule that lacks the data it needs; the runner reports `not_assessed` with the reason."""


class RuleMeta(BaseModel):
    id: str
    category: str
    severity: Severity
    privilege_required: Literal["standard", "privileged"] = "standard"
    requires_coverage: list[str]
    title: Localized
    why_it_matters: Localized
    remediation: Localized
    control_mappings: dict[str, list[str]] = Field(default_factory=dict)
    attack_techniques: list[str] = Field(default_factory=list)
    matches_pingcastle_rule: str | None = None
    evidence_source: str
    params: dict[str, Any] = Field(default_factory=dict)

    @field_validator("requires_coverage")
    @classmethod
    def _known(cls, keys: list[str]) -> list[str]:
        unknown = [k for k in keys if k not in COVERAGE_KEYS]
        if unknown:
            raise ValueError(f"unknown coverage keys {unknown}; allowed: {COVERAGE_KEYS}")
        return keys


@dataclass(frozen=True)
class RuleContext:
    mode: str  # "standard" | "privileged"


Evaluator = Callable[[Snapshot, RuleMeta, RuleContext], list[Finding]]


@dataclass(frozen=True)
class Rule:
    meta: RuleMeta
    evaluate: Evaluator


def ps_literal(value: str) -> str:
    """`value` as a PowerShell single-quoted string, so nothing in it is expanded or run.

    Every PowerShell single-quote character (' and the typographic ‘ ’ ‚ ‛) is doubled, as
    CodeGeneration.EscapeSingleQuotedStringContent does.
    """
    return "'" + re.sub("(['‘’‚‛])", r"\1\1", value) + "'"


def finding(
    meta: RuleMeta, obj: ADObject, evidence: dict[str, Any], *, confidence: Confidence = "high",
    fill: dict[str, str] | None = None,
) -> Finding:
    """One finding on `obj`; `<account>` in the remediation becomes its name, ready to paste into PowerShell.

    `fill` sets other placeholders (e.g. `<attributes>`); its values come from the rule, never from the directory.
    """
    values = {"<account>": ps_literal(obj.name), **(fill or {})}

    def filled(text: str) -> str:
        for placeholder, value in values.items():
            text = text.replace(placeholder, value)
        return text

    return Finding(
        rule_id=meta.id,
        category=meta.category,
        severity=meta.severity,
        title=meta.title,
        why_it_matters=meta.why_it_matters,
        remediation=Localized(en=filled(meta.remediation.en), ar=filled(meta.remediation.ar)),
        affected_object=obj.object_id,
        affected_object_type=obj.object_type,
        affected_name=obj.name,
        evidence=evidence,
        evidence_source=meta.evidence_source,
        control_mappings=meta.control_mappings,
        attack_techniques=meta.attack_techniques,
        confidence=confidence,
    )


def _accounts(snapshot: Snapshot, object_type: ObjectType, kind: str, fields: tuple[str, ...]) -> list[ADObject]:
    accounts = snapshot.by_type(object_type)
    if not accounts:
        raise NotAssessed(f"no {kind} accounts were collected")
    known = [a for a in accounts if all(a.derived.get(f) is not None for f in fields)]
    if not known:
        raise NotAssessed(f"{', '.join(fields)} could not be read on any {kind} account")
    return sorted(known, key=lambda a: a.name.lower())


def user_accounts(snapshot: Snapshot, *fields: str) -> list[ADObject]:
    """User accounts whose `fields` were collected, sorted by name; NotAssessed when there are none."""
    return _accounts(snapshot, ObjectType.USER, "user", fields)


def computer_accounts(snapshot: Snapshot, *fields: str) -> list[ADObject]:
    """Computer accounts whose `fields` were collected, sorted by name; NotAssessed when there are none."""
    return _accounts(snapshot, ObjectType.COMPUTER, "computer", fields)


def load_catalog() -> list[Rule]:
    """Discover `<rule>.yaml` + `<rule>.py` pairs in this package, sorted by rule id."""
    rules: list[Rule] = []
    for entry in importlib.resources.files("adrules.catalog").iterdir():
        if entry.name.endswith(".yaml"):
            meta = RuleMeta.model_validate(yaml.safe_load(entry.read_text(encoding="utf-8")))
            module = importlib.import_module(f"adrules.catalog.{entry.name[:-5]}")
            rules.append(Rule(meta=meta, evaluate=module.evaluate))
    return sorted(rules, key=lambda r: r.meta.id)


def run_rule(rule: Rule, snapshot: Snapshot, ctx: RuleContext) -> CheckResult:
    meta = rule.meta
    missing = [k for k in meta.requires_coverage if snapshot.coverage_of(k) is CoverageLevel.NONE]
    if missing:
        return CheckResult(rule_id=meta.id, status=Status.NOT_ASSESSED, reason=f"coverage {', '.join(missing)} is none")
    if meta.privilege_required == "privileged" and ctx.mode != "privileged":
        return CheckResult(rule_id=meta.id, status=Status.NEEDS_ELEVATED, reason="rule needs privileged collection")
    partial = any(snapshot.coverage_of(k) is CoverageLevel.PARTIAL for k in meta.requires_coverage)
    confidence: Confidence = "medium" if partial else "high"
    try:
        findings = rule.evaluate(snapshot, meta, ctx)
    except NotAssessed as exc:
        return CheckResult(rule_id=meta.id, status=Status.NOT_ASSESSED, reason=str(exc))
    if partial:
        findings = [f.model_copy(update={"confidence": "medium"}) for f in findings]
    return CheckResult(rule_id=meta.id, status=Status.FAIL if findings else Status.PASS, confidence=confidence, findings=findings)


def run_all(snapshot: Snapshot, rules: list[Rule] | None = None) -> list[CheckResult]:
    ctx = RuleContext(mode=snapshot.snapshot.collector.mode)
    return [run_rule(r, snapshot, ctx) for r in (rules if rules is not None else load_catalog())]
