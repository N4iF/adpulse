from adsnap.model import CoverageLevel, ObjectType
from adsnap.testing import DOMAIN_SID, make_domain, make_snapshot, make_user


def test_default_domain_is_healthy_and_coverage_is_directory_only() -> None:
    snap = make_snapshot()
    d = snap.domain()
    assert d.object_type is ObjectType.DOMAIN and d.object_sid == DOMAIN_SID
    assert d.derived == {"min_password_length": 14, "password_complexity": True, "lockout_threshold": 5}
    assert snap.coverage_of("directory_objects") is CoverageLevel.FULL
    assert snap.coverage_of("acls") is CoverageLevel.NONE


def test_make_user_defaults_are_a_healthy_enabled_account() -> None:
    u = make_user("temp.intern", rid=1105, passwd_notreqd=True)
    assert u.object_type is ObjectType.USER and u.object_sid == f"{DOMAIN_SID}-1105" and u.name == "temp.intern"
    assert u.derived == {"enabled": True, "is_builtin": False, "passwd_notreqd": True, "asrep_roastable": False}
    assert make_user("Guest", rid=501).derived["is_builtin"] is True


def test_overrides() -> None:
    snap = make_snapshot(make_domain(min_password_length=6), coverage={"directory_objects": CoverageLevel.PARTIAL})
    assert snap.domain().derived["min_password_length"] == 6
    assert snap.coverage_of("directory_objects") is CoverageLevel.PARTIAL
