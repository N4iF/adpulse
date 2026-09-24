"""ACC-01: an enabled user account may have an empty password (PASSWD_NOTREQD)."""

from adrules.catalog import RuleContext, RuleMeta, finding, user_accounts
from adrules.finding import Finding
from adsnap.model import Snapshot


def evaluate(snapshot: Snapshot, meta: RuleMeta, ctx: RuleContext) -> list[Finding]:
    return [
        finding(meta, user, {
            "account": user.name, "setting": "userAccountControl",
            "current": "password not required (PASSWD_NOTREQD, 0x20)", "expected": "flag cleared, strong password set",
        })
        for user in user_accounts(snapshot, "enabled", "passwd_notreqd")
        if user.derived["enabled"] and user.derived["passwd_notreqd"]
    ]
