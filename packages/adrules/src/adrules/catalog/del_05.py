"""DEL-05: any user may add computers to the domain (ms-DS-MachineAccountQuota above 0)."""

from adrules.catalog import NotAssessed, RuleContext, RuleMeta, finding
from adrules.finding import Finding
from adsnap.model import Snapshot


def evaluate(snapshot: Snapshot, meta: RuleMeta, ctx: RuleContext) -> list[Finding]:
    domain = snapshot.domain()
    quota = domain.derived.get("machine_account_quota")
    if quota is None:
        raise NotAssessed("ms-DS-MachineAccountQuota was not collected from the domain object")
    if int(quota) <= 0:
        return []
    return [finding(meta, domain, {"setting": "ms-DS-MachineAccountQuota", "current": int(quota), "expected": 0})]
