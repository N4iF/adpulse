from adrules.finding import CheckResult, Finding, Localized, Severity, Status
from adsnap.model import ObjectType


def _finding(subject: str | None = None) -> Finding:
    return Finding(
        rule_id="ACL-01", category="acl", severity=Severity.CRITICAL,
        title=Localized(en="t", ar="ت"), why_it_matters=Localized(en="w", ar="و"), remediation=Localized(en="r", ar="ر"),
        affected_object="guid-domain", affected_object_type=ObjectType.DOMAIN, affected_name="corp.local",
        subject_id=subject, evidence={"rights": ["ExtendedRight:DS-Replication-Get-Changes"]}, evidence_source="nTSecurityDescriptor",
        control_mappings={"nca_ecc_2_2024": ["2-2-3-3"]}, attack_techniques=["T1003.006"],
    )


def test_finding_key_includes_subject() -> None:
    assert _finding("guid-svc_backup").key == ("ACL-01", "guid-domain", "guid-svc_backup")
    assert _finding().key == ("ACL-01", "guid-domain", None)


def test_check_result_status_values() -> None:
    r = CheckResult(rule_id="ACL-01", status=Status.NOT_ASSESSED, reason="coverage acls is none")
    assert r.findings == []
    assert Status("pass") is Status.PASS
    assert r.model_dump()["status"] == "not_assessed"
