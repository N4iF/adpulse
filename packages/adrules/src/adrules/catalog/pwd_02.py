"""PWD-02: password complexity disabled on the domain."""

from adrules.catalog import NotAssessed, RuleContext, RuleMeta, finding
from adrules.finding import Finding
from adsnap.model import Snapshot


def evaluate(snapshot: Snapshot, meta: RuleMeta, ctx: RuleContext) -> list[Finding]:
    domain = snapshot.domain()
    complexity = domain.derived.get("password_complexity")
    if complexity is None:
        raise NotAssessed("pwdProperties was not collected from the domain object")
    if complexity:
        return []
    return [finding(meta, domain, {"setting": "pwdProperties (complexity)", "current": "off", "expected": "on"})]
