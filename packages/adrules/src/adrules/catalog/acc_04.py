"""ACC-04: an account's description, info or comment mentions a password (only the indicator is stored)."""

from adrules.catalog import RuleContext, RuleMeta, finding, user_accounts
from adrules.finding import Finding
from adsnap.model import Snapshot


def evaluate(snapshot: Snapshot, meta: RuleMeta, ctx: RuleContext) -> list[Finding]:
    return [
        finding(meta, user, {
            "account": user.name, "setting": ", ".join(user.derived["password_in_text_attrs"]),
            "current": "mentions a password (the text is not stored)", "expected": "no passwords in account attributes",
        }, fill={"<attributes>": ",".join(user.derived["password_in_text_attrs"])})  # adsnap's own attribute names
        for user in user_accounts(snapshot, "password_in_text_indicator", "password_in_text_attrs")
        if user.derived["password_in_text_indicator"]  # enabled or not: the text is readable either way
    ]
