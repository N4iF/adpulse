"""PWD-04: account lockout disabled (0) or too permissive (> params.max_threshold)."""

from adrules.catalog import NotAssessed, RuleContext, RuleMeta, finding
from adrules.finding import Finding
from adsnap.model import Snapshot


def evaluate(snapshot: Snapshot, meta: RuleMeta, ctx: RuleContext) -> list[Finding]:
    domain = snapshot.domain()
    limit = int(meta.params.get("max_threshold", 10))
    threshold = domain.derived.get("lockout_threshold")
    if threshold is None:
        raise NotAssessed("lockoutThreshold was not collected from the domain object")
    if 1 <= int(threshold) <= limit:
        return []
    return [finding(meta, domain, {"setting": "lockoutThreshold", "current": int(threshold), "expected": f"1-{limit}"})]
