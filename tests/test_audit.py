from __future__ import annotations

from msad.audit import (
    DEFAULT_DOMAIN_ATTRIBUTES,
    DEFAULT_PASSWORD_POLICY_ATTRIBUTES,
    DEFAULT_PRIVILEGED_GROUPS,
    get_domain_info,
    get_password_policy,
    get_privileged_groups,
)


def test_get_domain_info_filter_and_attrs(conn, make_entry) -> None:
    conn.queue([make_entry({"name": "example", "maxPwdAge": -1}, dn="DC=example,DC=com")])
    result = get_domain_info(conn, "DC=example,DC=com")
    last = conn.searches[-1]
    assert last.search_base == "DC=example,DC=com"
    assert last.search_filter == "(objectClass=domainDNS)"
    assert last.attributes == DEFAULT_DOMAIN_ATTRIBUTES
    assert result is not None
    assert result["name"] == "example"


def test_get_domain_info_returns_none_when_absent(conn) -> None:
    conn.queue([])
    assert get_domain_info(conn, "DC=example,DC=com") is None


def test_get_password_policy_reads_domain(conn, make_entry) -> None:
    conn.queue([make_entry({"minPwdLength": 8, "lockoutThreshold": 5}, dn="DC=example,DC=com")])
    result = get_password_policy(conn, "DC=example,DC=com")
    last = conn.searches[-1]
    assert last.search_filter == "(objectClass=domainDNS)"
    assert last.attributes == DEFAULT_PASSWORD_POLICY_ATTRIBUTES
    assert result is not None
    assert result["minPwdLength"] == 8


def test_default_privileged_group_list_has_domain_admins() -> None:
    assert "Domain Admins" in DEFAULT_PRIVILEGED_GROUPS
    assert "Enterprise Admins" in DEFAULT_PRIVILEGED_GROUPS


def test_get_privileged_groups_reports_member_count(conn, make_entry) -> None:
    grp_dn = "CN=Domain Admins,CN=Users,DC=example,DC=com"
    # 1) get_group -> the group object
    conn.queue([make_entry({"cn": "Domain Admins", "sAMAccountName": "Domain Admins"}, dn=grp_dn)])
    # 2) group_members -> get_dn resolves the group DN
    conn.queue([make_entry({"distinguishedName": grp_dn}, dn=grp_dn)])
    # 3) group_members -> the actual members
    conn.queue(
        [
            make_entry({"sAMAccountName": "admin1"}, dn="CN=admin1,DC=example,DC=com"),
            make_entry({"sAMAccountName": "admin2"}, dn="CN=admin2,DC=example,DC=com"),
        ]
    )

    report = get_privileged_groups(conn, "DC=example,DC=com", names=["Domain Admins"])

    assert len(report) == 1
    assert report[0]["member_count"] == 2
    assert "members" not in report[0]  # with_members defaults to False


def test_get_privileged_groups_skips_absent(conn) -> None:
    conn.queue([])  # get_group finds nothing
    report = get_privileged_groups(conn, "DC=example,DC=com", names=["Nonexistent Group"])
    assert report == []


def test_get_privileged_groups_with_members(conn, make_entry) -> None:
    grp_dn = "CN=Backup Operators,CN=Builtin,DC=example,DC=com"
    conn.queue([make_entry({"cn": "Backup Operators"}, dn=grp_dn)])
    conn.queue([make_entry({"distinguishedName": grp_dn}, dn=grp_dn)])
    conn.queue([make_entry({"sAMAccountName": "op1"}, dn="CN=op1,DC=example,DC=com")])

    report = get_privileged_groups(
        conn, "DC=example,DC=com", names=["Backup Operators"], with_members=True
    )

    assert report[0]["member_count"] == 1
    assert report[0]["members"][0]["sAMAccountName"] == "op1"


def test_pwd_violations_builds_expired_filter(conn, make_entry) -> None:
    from msad.audit import DEFAULT_PWD_VIOLATION_ATTRIBUTES, get_password_policy_violations

    # 1) get_password_policy -> policy with a 42-day maxPwdAge (negative FILETIME)
    conn.queue([make_entry({"maxPwdAge": -36288000000000}, dn="DC=example,DC=com")])
    # 2) the user search
    conn.queue([make_entry({"sAMAccountName": "old"}, dn="CN=old,DC=example,DC=com")])

    result = get_password_policy_violations(conn, "DC=example,DC=com")

    f = conn.searches[-1].search_filter
    assert "(objectClass=user)" in f
    assert "(objectCategory=person)" in f
    assert "(pwdLastSet<=" in f
    assert "(pwdLastSet=0)" in f  # include_never_set defaults True
    assert "1.2.840.113556.1.4.803:=65536" in f  # excludes DONT_EXPIRE_PASSWORD
    assert conn.searches[-1].attributes == DEFAULT_PWD_VIOLATION_ATTRIBUTES
    assert len(result) == 1


def test_pwd_violations_exclude_never_set(conn, make_entry) -> None:
    from msad.audit import get_password_policy_violations

    conn.queue([make_entry({"maxPwdAge": -36288000000000}, dn="DC=example,DC=com")])
    conn.queue([])
    get_password_policy_violations(conn, "DC=example,DC=com", include_never_set=False)
    f = conn.searches[-1].search_filter
    assert "(pwdLastSet<=" in f
    assert "(pwdLastSet=0)" not in f


def test_pwd_violations_no_policy_returns_empty(conn) -> None:
    from msad.audit import get_password_policy_violations

    conn.queue([])  # get_password_policy finds nothing
    assert get_password_policy_violations(conn, "DC=example,DC=com") == []


def test_pwd_violations_zero_maxpwdage_returns_empty(conn, make_entry) -> None:
    from msad.audit import get_password_policy_violations

    # maxPwdAge = 0 -> passwords never expire domain-wide
    conn.queue([make_entry({"maxPwdAge": 0}, dn="DC=example,DC=com")])
    assert get_password_policy_violations(conn, "DC=example,DC=com") == []


def test_max_pwd_age_span_handles_timedelta() -> None:
    import datetime

    from msad.audit import _max_pwd_age_filetime_span

    assert _max_pwd_age_filetime_span(datetime.timedelta(days=42)) == 42 * 86400 * 10_000_000
    assert _max_pwd_age_filetime_span(-36288000000000) == 36288000000000
    assert _max_pwd_age_filetime_span(0) is None
    assert _max_pwd_age_filetime_span(None) is None
