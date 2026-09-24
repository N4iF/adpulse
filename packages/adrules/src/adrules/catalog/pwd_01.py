"""PWD-01: domain minimum password length below params.min_length."""

from adrules.catalog import NotAssessed, RuleContext, RuleMeta, finding
from adrules.finding import Finding
from adsnap.model import Snapshot


def evaluate(snapshot: Snapshot, meta: RuleMeta, ctx: RuleContext) -> list[Finding]:
    domain = snapshot.domain()
    minimum = int(meta.params.get("min_length", 12))
    length = domain.derived.get("min_password_length")
    if length is None:
        raise NotAssessed("minPwdLength was not collected from the domain object")
    if int(length) >= minimum:
        return []
    return [finding(meta, domain, {"setting": "minPwdLength", "current": int(length), "expected": f">= {minimum}"})]
