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


# --- FSMO roles -------------------------------------------------------------


def test_list_fsmo_roles_queries_five_containers(conn, make_entry) -> None:
    from msad.audit import list_fsmo_roles

    base = "DC=example,DC=com"
    dsa = "CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site"
    # One queued response per role container, in the order the function queries.
    for _ in range(5):
        conn.queue([make_entry({"fSMORoleOwner": dsa}, dn="x")])

    report = list_fsmo_roles(conn, base)

    roles = [r["role"] for r in report]
    assert roles == [
        "schema_master",
        "domain_naming_master",
        "pdc_emulator",
        "rid_master",
        "infrastructure_master",
    ]
    # Schema/Partitions resolve against the Configuration NC; domain roles against base.
    bases = [s.search_base for s in conn.searches]
    assert "CN=Schema,CN=Configuration,DC=example,DC=com" in bases
    assert "CN=Partitions,CN=Configuration,DC=example,DC=com" in bases
    assert base in bases
    assert "CN=RID Manager$,CN=System,DC=example,DC=com" in bases
    assert all(r["owner"] == dsa for r in report)


def test_list_fsmo_roles_unwraps_list_owner(conn, make_entry) -> None:
    from msad.audit import list_fsmo_roles

    # ldap3 may return fSMORoleOwner as a single-item list.
    conn.queue([make_entry({"fSMORoleOwner": ["CN=dsa"]}, dn="x")])
    for _ in range(4):
        conn.queue([])
    report = list_fsmo_roles(conn, "DC=example,DC=com")
    assert report[0]["owner"] == "CN=dsa"


def test_list_fsmo_roles_respects_config_base(conn, make_entry) -> None:
    from msad.audit import list_fsmo_roles

    for _ in range(5):
        conn.queue([make_entry({"fSMORoleOwner": "CN=dsa"}, dn="x")])
    list_fsmo_roles(
        conn, "DC=child,DC=example,DC=com", config_base="CN=Configuration,DC=example,DC=com"
    )
    bases = [s.search_base for s in conn.searches]
    assert "CN=Schema,CN=Configuration,DC=example,DC=com" in bases


# --- Trusts -----------------------------------------------------------------


def test_list_trusts_filter_and_base(conn, make_entry) -> None:
    from msad.audit import DEFAULT_TRUST_ATTRIBUTES, list_trusts

    conn.queue([make_entry({"trustPartner": "other.example.com"}, dn="CN=other,CN=System,DC=x")])
    result = list_trusts(conn, "DC=example,DC=com")
    last = conn.searches[-1]
    assert last.search_base == "CN=System,DC=example,DC=com"
    assert last.search_filter == "(objectClass=trustedDomain)"
    assert last.attributes == DEFAULT_TRUST_ATTRIBUTES
    assert result[0]["trustPartner"] == "other.example.com"


def test_list_trusts_empty(conn) -> None:
    from msad.audit import list_trusts

    conn.queue([])
    assert list_trusts(conn, "DC=example,DC=com") == []


# --- Sites ------------------------------------------------------------------


def test_list_sites_filter_and_base(conn, make_entry) -> None:
    from msad.audit import DEFAULT_SITE_ATTRIBUTES, list_sites

    conn.queue([make_entry({"cn": "Default-First-Site-Name"}, dn="CN=...,CN=Sites")])
    result = list_sites(conn, "DC=example,DC=com")
    last = conn.searches[-1]
    assert last.search_base == "CN=Sites,CN=Configuration,DC=example,DC=com"
    assert last.search_filter == "(objectClass=site)"
    assert last.attributes == DEFAULT_SITE_ATTRIBUTES
    assert result[0]["cn"] == "Default-First-Site-Name"


def test_list_sites_respects_config_base(conn) -> None:
    from msad.audit import list_sites

    conn.queue([])
    list_sites(conn, "DC=child,DC=example,DC=com", config_base="CN=Configuration,DC=example,DC=com")
    assert conn.searches[-1].search_base == "CN=Sites,CN=Configuration,DC=example,DC=com"


# --- GPOs -------------------------------------------------------------------


def test_list_gpos_filter_and_base(conn, make_entry) -> None:
    from msad.audit import DEFAULT_GPO_ATTRIBUTES, list_gpos

    conn.queue([make_entry({"displayName": "Default Domain Policy"}, dn="CN={GUID},CN=Policies")])
    result = list_gpos(conn, "DC=example,DC=com")
    last = conn.searches[-1]
    assert last.search_base == "CN=Policies,CN=System,DC=example,DC=com"
    assert last.search_filter == "(objectClass=groupPolicyContainer)"
    assert last.attributes == DEFAULT_GPO_ATTRIBUTES
    assert result[0]["displayName"] == "Default Domain Policy"


def test_get_gpo_matches_cn_braced_and_displayname(conn, make_entry) -> None:
    from msad.audit import get_gpo

    conn.queue(
        [make_entry({"cn": "{31B2F340-016D-11D2-945F-00C04FB984F9}"}, dn="CN=...,CN=Policies")]
    )
    result = get_gpo(conn, "DC=example,DC=com", "31B2F340-016D-11D2-945F-00C04FB984F9")
    f = conn.searches[-1].search_filter
    assert "(objectClass=groupPolicyContainer)" in f
    assert "(cn=31B2F340-016D-11D2-945F-00C04FB984F9)" in f
    assert "(cn={31B2F340-016D-11D2-945F-00C04FB984F9})" in f  # braces tried too
    assert "(displayName=31B2F340-016D-11D2-945F-00C04FB984F9)" in f
    assert result is not None


def test_get_gpo_returns_none_when_absent(conn) -> None:
    from msad.audit import get_gpo

    conn.queue([])
    assert get_gpo(conn, "DC=example,DC=com", "Nonexistent") is None


# --- Fine-grained password policies (PSOs) ----------------------------------


def test_list_psos_filter_and_base(conn, make_entry) -> None:
    from msad.audit import DEFAULT_PSO_ATTRIBUTES, list_fine_grained_password_policies

    conn.queue(
        [make_entry({"cn": "PSO-Admins"}, dn="CN=PSO-Admins,CN=Password Settings Container")]
    )
    result = list_fine_grained_password_policies(conn, "DC=example,DC=com")
    last = conn.searches[-1]
    assert last.search_base == "CN=Password Settings Container,CN=System,DC=example,DC=com"
    assert last.search_filter == "(objectClass=msDS-PasswordSettings)"
    assert last.attributes == DEFAULT_PSO_ATTRIBUTES
    assert result[0]["cn"] == "PSO-Admins"
