#!/usr/bin/env python3
"""
Generate a small synthetic BloodHound CE (v6) dataset with planted exposures,
so the viewer can be tested without a real collection. NOT real data.

Run:  python generate_sample.py
Output: sample/*.json  (users, computers, groups, domains, gpos, ous, containers)
"""
import json, os, time

HERE = os.path.dirname(os.path.abspath(__file__))
DOMAIN = "CORP.LOCAL"
DSID = "S-1-5-21-1111111111-2222222222-3333333333"
now = int(time.time())
DAY = 86400


def dn(cn, *ous):
    parts = ["CN=" + cn] + ["OU=" + o for o in ous] + ["DC=CORP", "DC=LOCAL"]
    return ",".join(parts)


def user(rid, name, **p):
    sid = DSID + "-" + str(rid)
    props = {
        "domain": DOMAIN, "name": name + "@" + DOMAIN, "distinguishedname": dn(name, "Users"),
        "domainsid": DSID, "samaccountname": name, "enabled": True,
        "pwdlastset": now - 30 * DAY, "lastlogontimestamp": now - 5 * DAY,
        "serviceprincipalnames": [], "hasspn": False, "dontreqpreauth": False,
        "passwordnotreqd": False, "unconstraineddelegation": False, "trustedtoauth": False,
        "sensitive": False, "admincount": False, "pwdneverexpires": False,
        "sidhistory": [], "objectid": sid,
    }
    props.update(p)
    return {
        "Properties": props, "ObjectIdentifier": sid, "Aces": p.get("_aces", []),
        "AllowedToDelegate": p.get("_atd", []), "HasSIDHistory": p.get("_sidhist", []),
        "PrimaryGroupSID": DSID + "-513", "IsDeleted": False, "IsACLProtected": False,
    }


def computer(rid, name, **p):
    sid = DSID + "-" + str(rid)
    props = {
        "domain": DOMAIN, "name": name + "." + DOMAIN, "distinguishedname": dn(name, "Computers"),
        "domainsid": DSID, "samaccountname": name + "$", "enabled": True,
        "operatingsystem": "Windows Server 2019 Standard",
        "lastlogontimestamp": now - 3 * DAY, "pwdlastset": now - 20 * DAY,
        "unconstraineddelegation": False, "trustedtoauth": False, "haslaps": True,
        "objectid": sid,
    }
    props.update({k: v for k, v in p.items() if not k.startswith("_")})
    return {
        "Properties": props, "ObjectIdentifier": sid, "Aces": p.get("_aces", []),
        "AllowedToDelegate": p.get("_atd", []), "PrimaryGroupSID": DSID + "-515",
        "IsDeleted": False, "IsACLProtected": False,
    }


def group(rid, name, members, admincount=False, aces=None):
    sid = rid if str(rid).startswith("S-1-5-32") else DSID + "-" + str(rid)
    return {
        "Properties": {"domain": DOMAIN, "name": name + "@" + DOMAIN,
                       "distinguishedname": dn(name, "Groups"), "admincount": admincount,
                       "objectid": sid},
        "ObjectIdentifier": sid,
        "Members": [{"ObjectIdentifier": m, "ObjectType": "User"} for m in members],
        "Aces": aces or [], "IsDeleted": False, "IsACLProtected": False,
    }


def ace(psid, right, ptype="User", inherited=False):
    return {"PrincipalSID": psid, "PrincipalType": ptype, "RightName": right, "IsInherited": inherited}


def wrap(objs, typ):
    return {"data": objs, "meta": {"methods": 0, "type": typ, "count": len(objs), "version": 6}}


def write(typ, objs):
    path = os.path.join(HERE, "%s_%s.json" % (DOMAIN.split(".")[0].lower(), typ))
    with open(path, "w", encoding="utf-8") as f:
        json.dump(wrap(objs, typ), f, indent=1)
    print("wrote", os.path.basename(path), len(objs))


# ---- users ----------------------------------------------------------------
users = []
users.append(user(500, "Administrator", admincount=True))
users.append(user(501, "Guest", enabled=True))                      # guest-enabled
users.append(user(502, "krbtgt", enabled=False, admincount=True))

# privileged, kerberoastable service account (planted -> kerberoast-privileged)
users.append(user(1104, "svc_sql", admincount=True, hasspn=True,
                  serviceprincipalnames=["MSSQLSvc/db01.corp.local:1433"],
                  pwdneverexpires=True, pwdlastset=now - 900 * DAY))
# normal kerberoastable
users.append(user(1105, "svc_web", hasspn=True,
                  serviceprincipalnames=["HTTP/web01.corp.local"]))
# AS-REP roastable
users.append(user(1106, "legacy_app", dontreqpreauth=True))
# password not required
users.append(user(1107, "kiosk", passwordnotreqd=True))
# constrained delegation
users.append(user(1108, "svc_deleg", _atd=[{"ObjectIdentifier": DSID + "-1201"}], trustedtoauth=True))
# admincount orphan (not in any priv group)
users.append(user(1109, "ex_admin", admincount=True))
# sid history -> Domain Admins
users.append(user(1110, "migrated", _sidhist=[{"ObjectIdentifier": DSID + "-512"}],
                  sidhistory=[DSID + "-512"]))
# dormant + old password
users.append(user(1111, "old_hank", lastlogontimestamp=now - 400 * DAY, pwdlastset=now - 500 * DAY))
users.append(user(1112, "dusty", lastlogontimestamp=now - 250 * DAY))
# never-expires
users.append(user(1113, "batchjob", pwdneverexpires=True))
# a couple of plain admins for the DA group / protected-users check
users.append(user(1101, "alice_da", admincount=True))
users.append(user(1102, "bob_da", admincount=True))
users.append(user(1103, "carol_da", admincount=True, enabled=False))  # disabled-in-priv-group
users.append(user(1120, "dave_ea", admincount=True))
users.append(user(1121, "erin_ea", admincount=True))
# filler users
for i in range(40):
    users.append(user(2000 + i, "user%02d" % i))

# ---- computers ------------------------------------------------------------
computers = []
computers.append(computer(1001, "DC01", operatingsystem="Windows Server 2019 Datacenter",
                          unconstraineddelegation=True))  # DC: unconstrained is OK, must NOT flag
computers.append(computer(1002, "FILE01", haslaps=False))                 # laps-missing
computers.append(computer(1003, "APP01", unconstraineddelegation=True, haslaps=False))  # unconstrained non-DC
computers.append(computer(1004, "OLDBOX", operatingsystem="Windows 7 Enterprise", haslaps=False))  # obsolete-os
computers.append(computer(1201, "SQL01"))
for i in range(8):
    computers.append(computer(3000 + i, "WS%02d" % i, haslaps=(i % 2 == 0)))

# ---- hygiene & lifecycle planted cases ------------------------------------
# privileged dormant + privileged never-used (dormant-privileged-account)
users.append(user(1130, "old_da", admincount=True, lastlogontimestamp=now - 400 * DAY))
users.append(user(1131, "unused_da", admincount=True, lastlogontimestamp=0, lastlogon=0))
# duplicate sAMAccountName across two objects (duplicate-objects)
users.append(user(1132, "dupuser"))
users.append(user(1133, "dupuser"))
# replication conflict object (duplicate-objects)
_cnf = user(1134, "conflicted")
_cnf["Properties"]["distinguishedname"] = "CN=conflicted\\0ACNF:8a7b,OU=Users,DC=CORP,DC=LOCAL"
users.append(_cnf)

# privileged computer on an obsolete OS (obsolete-os-privileged)
computers.append(computer(1005, "OLDDC", operatingsystem="Windows Server 2008 R2 Standard",
                          haslaps=False))
# dormant DC (dormant-domain-controller) - DC02 has not logged on for a year
computers.append(computer(1006, "DC02", operatingsystem="Windows Server 2016 Datacenter",
                          lastlogontimestamp=now - 365 * DAY))

# ---- groups ---------------------------------------------------------------
DA = [DSID + "-1101", DSID + "-1102", DSID + "-1103", DSID + "-1104",
      DSID + "-2000", DSID + "-2001", DSID + "-2002",
      DSID + "-1130", DSID + "-1131"]  # 9 members -> too-many + disabled + dormant admins
EA = [DSID + "-1120", DSID + "-1121"]
groups = []
groups.append(group(512, "DOMAIN ADMINS", DA, admincount=True))
groups.append(group(519, "ENTERPRISE ADMINS", EA, admincount=True))
groups.append(group("S-1-5-32-544", "ADMINISTRATORS", [DSID + "-512", DSID + "-519"], admincount=True,
                    aces=[ace(DSID + "-1109", "WriteDacl")]))  # dangerous ACL on tier-0 group
groups.append(group(525, "PROTECTED USERS", [DSID + "-1101"]))  # only alice is protected
# OLDDC (obsolete OS) and DC02 (dormant) are Domain Controllers
groups.append(group(516, "DOMAIN CONTROLLERS", [DSID + "-1001", DSID + "-1005", DSID + "-1006"]))
groups.append(group(513, "DOMAIN USERS", [u["ObjectIdentifier"] for u in users]))
# hygiene: empty / single-member groups, privileged and not (priv-group-size, group-size-hygiene)
groups.append(group(548, "ACCOUNT OPERATORS", [], admincount=True))          # empty privileged
groups.append(group(551, "BACKUP OPERATORS", [DSID + "-1102"], admincount=True))  # single-member priv
groups.append(group(4001, "PROJECT-ARCHIVE", []))                            # empty non-priv
groups.append(group(4002, "APP-OWNERS", [DSID + "-2003"]))                   # single-member non-priv

# ---- domain (with a planted DCSync grant + shadow-cred + machinequota) -----
CHILD_SID = "S-1-5-21-4444444444-5555555555-6666666666"
PARTNER_SID = "S-1-5-21-7777777777-8888888888-9999999999"
OTHERFOREST_SID = "S-1-5-21-1212121212-3434343434-5656565656"

TRUSTS = [
    # intra-forest: SID filtering is off BY DESIGN -> must NOT be flagged
    {"TargetDomainSid": CHILD_SID, "TargetDomainName": "CHILD.CORP.LOCAL",
     "IsTransitive": True, "TrustDirection": "Bidirectional", "TrustType": "ParentChild",
     "SidFilteringEnabled": False},
    # external, no SID filtering, transitive -> sid-filtering + transitive-external + uncollected
    {"TargetDomainSid": PARTNER_SID, "TargetDomainName": "PARTNER.EXTERNAL",
     "IsTransitive": True, "TrustDirection": "Bidirectional", "TrustType": "External",
     "SidFilteringEnabled": False},
    # numeric enums (older collector): TrustType 2 = Forest, TrustDirection 1 = Inbound
    {"TargetDomainSid": OTHERFOREST_SID, "TargetDomainName": "OTHERFOREST.LOCAL",
     "IsTransitive": True, "TrustDirection": 1, "TrustType": 2,
     "SidFilteringEnabled": True, "TGTDelegationEnabled": True},
]

domains = [{
    "Properties": {"name": DOMAIN, "domain": DOMAIN, "domainsid": DSID,
                   "functionallevel": "2008 R2", "ms-ds-machineaccountquota": 10,
                   "distinguishedname": "DC=CORP,DC=LOCAL", "objectid": DSID},
    "ObjectIdentifier": DSID,
    "Aces": [ace(DSID + "-1105", "DCSync"),               # svc_web can DCSync -> critical
             ace(DSID + "-1109", "GetChangesAll")],
    "Trusts": TRUSTS, "Links": [], "ChildObjects": [], "GPOChanges": {},
    "IsDeleted": False, "IsACLProtected": False,
}, {
    # child domain IS collected -> the ParentChild trust must NOT raise "uncollected"
    "Properties": {"name": "CHILD.CORP.LOCAL", "domain": "CHILD.CORP.LOCAL",
                   "domainsid": CHILD_SID, "functionallevel": "2016",
                   "distinguishedname": "DC=CHILD,DC=CORP,DC=LOCAL", "objectid": CHILD_SID},
    "ObjectIdentifier": CHILD_SID,
    "Aces": [], "Trusts": [], "Links": [], "ChildObjects": [], "GPOChanges": {},
    "IsDeleted": False, "IsACLProtected": False,
}]

# shadow credentials: give 'kiosk' AddKeyCredentialLink over 'alice_da'
for u in users:
    if u["Properties"]["samaccountname"] == "alice_da":
        u["Aces"].append(ace(DSID + "-1107", "AddKeyCredentialLink"))

gpos = [
    {"Properties": {"domain": DOMAIN, "name": "DEFAULT DOMAIN POLICY@" + DOMAIN,
                    "distinguishedname": dn("{31B2F340}", "Policies", "System"),
                    "objectid": "GPO-0001"}, "ObjectIdentifier": "GPO-0001", "Aces": []},
    # dangerous ACL: ex_admin can rewrite this linked GPO -> gpo-dangerous-acl
    {"Properties": {"domain": DOMAIN, "name": "WORKSTATION HARDENING@" + DOMAIN,
                    "distinguishedname": dn("{A1B2C3D4}", "Policies", "System"),
                    "objectid": "GPO-0002"}, "ObjectIdentifier": "GPO-0002",
     "Aces": [ace(DSID + "-1109", "WriteDacl")]},
    # orphaned / unlinked -> gpo-unlinked-disabled
    {"Properties": {"domain": DOMAIN, "name": "OLD LEGACY GPO@" + DOMAIN,
                    "distinguishedname": dn("{DEADBEEF}", "Policies", "System"),
                    "objectid": "GPO-0003"}, "ObjectIdentifier": "GPO-0003", "Aces": []},
]
ous = [{"Properties": {"domain": DOMAIN, "name": "USERS@" + DOMAIN, "objectid": "OU-0001",
                       "distinguishedname": "OU=Users,DC=CORP,DC=LOCAL"},
        "ObjectIdentifier": "OU-0001", "Aces": [],
        "Links": [{"GUID": "GPO-0002", "IsEnforced": False}], "ChildObjects": []}]

# link the default policy at the domain so link data exists (GPO-0003 stays orphaned)
domains[0]["Links"] = [{"GUID": "GPO-0001", "IsEnforced": False}]

# ---- ADCS: enterprise CA + certificate templates --------------------------
def template(name, oid_suffix, **p):
    props = {"domain": DOMAIN, "name": name.upper() + "@" + DOMAIN,
             "distinguishedname": dn(name, "Certificate Templates", "Public Key Services", "Services", "Configuration"),
             "objectid": "CT-" + oid_suffix, "enabled": True,
             "enrolleesuppliessubject": False, "requiresmanagerapproval": False,
             "authorizedsignatures": 0, "nosecurityextension": False,
             "authenticationenabled": False, "ekus": [], "effectiveekus": []}
    props.update({k: v for k, v in p.items() if not k.startswith("_")})
    return {"Properties": props, "ObjectIdentifier": "CT-" + oid_suffix,
            "Aces": p.get("_aces", []), "IsDeleted": False, "IsACLProtected": False}

CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
ANY_PURPOSE = "2.5.29.37.0"
ENROLL_AGENT = "1.3.6.1.4.1.311.20.2.1"
enroll_du = ace(DSID + "-513", "Enroll", "Group")           # Domain Users can enroll
enroll_au = ace("S-1-5-11", "Enroll", "Group")              # Authenticated Users

certtemplates = [
    # clean template (manager approval, no ESS)
    template("User", "user", authenticationenabled=True, ekus=[CLIENT_AUTH],
             effectiveekus=[CLIENT_AUTH], requiresmanagerapproval=True, _aces=[enroll_du]),
    # ESC1
    template("VulnUserAuth", "esc1", enrolleesuppliessubject=True, authenticationenabled=True,
             ekus=[CLIENT_AUTH], effectiveekus=[CLIENT_AUTH], _aces=[enroll_du]),
    # ESC2 (Any Purpose)
    template("AnyPurpose", "esc2", ekus=[ANY_PURPOSE], effectiveekus=[ANY_PURPOSE], _aces=[enroll_au]),
    # ESC3 (Enrollment Agent)
    template("EnrollAgent", "esc3", ekus=[ENROLL_AGENT], effectiveekus=[ENROLL_AGENT], _aces=[enroll_du]),
    # ESC4 (weak ACL: ex_admin has GenericAll)
    template("MiscTemplate", "esc4", ekus=[CLIENT_AUTH], effectiveekus=[CLIENT_AUTH],
             _aces=[ace(DSID + "-1109", "GenericAll")]),
    # ESC9 (no security extension)
    template("NoSecExt", "esc9", authenticationenabled=True, ekus=[CLIENT_AUTH],
             effectiveekus=[CLIENT_AUTH], nosecurityextension=True, _aces=[enroll_du]),
]

enterprisecas = [{
    "Properties": {"domain": DOMAIN, "name": "CORP-CA@" + DOMAIN, "caname": "CORP-CA",
                   "dnshostname": "ca01.corp.local", "objectid": "ECA-0001",
                   "isuserspecifiessanenabled": True},   # ESC6
    "ObjectIdentifier": "ECA-0001",
    "Aces": [ace(DSID + "-1107", "ManageCA", "User")],     # ESC7: kiosk can ManageCA
    "IsDeleted": False,
}]
containers = [{"Properties": {"domain": DOMAIN, "name": "ADMINSDHOLDER@" + DOMAIN, "objectid": "C-0001",
                             "distinguishedname": "CN=AdminSDHolder,CN=System,DC=CORP,DC=LOCAL"},
               "ObjectIdentifier": "C-0001",
               "Aces": [ace(DSID + "-1109", "GenericAll")]}]  # dangerous ACL on AdminSDHolder

write("users", users)
write("computers", computers)
write("groups", groups)
write("domains", domains)
write("gpos", gpos)
write("ous", ous)
write("containers", containers)
write("certtemplates", certtemplates)
write("enterprisecas", enterprisecas)

# ---- Entra ID (AzureHound format) -----------------------------------------
# AzureHound emits one file where every entry is {"kind": "AZ...", "data": {...}}.
import datetime

TENANT = "11111111-2222-3333-4444-555555555555"
GLOBAL_ADMIN = "62e90394-69f5-4237-9190-012177145e10"


def iso(days_ago):
    return (datetime.datetime.utcnow() - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def az_user(uid, name, enabled=True, last_sign_in_days=3, created_days=400, onprem=None):
    d = {"id": uid, "displayName": name, "userPrincipalName": name + "@corp.local",
         "accountEnabled": enabled, "createdDateTime": iso(created_days), "tenantId": TENANT}
    if last_sign_in_days is not None:
        d["signInActivity"] = {"lastSignInDateTime": iso(last_sign_in_days)}
    if onprem:
        d["onPremisesSecurityIdentifier"] = onprem
    return {"kind": "AZUser", "data": d}


azure = [
    {"kind": "AZTenant", "data": {"id": TENANT, "displayName": "CORP"}},
    # privileged + dormant  -> az-dormant-privileged-user
    az_user("u-ga-old", "cloudadmin_old", last_sign_in_days=300),
    # privileged + never signed in -> az-dormant-privileged-user
    az_user("u-ga-never", "cloudadmin_new", last_sign_in_days=None, created_days=200),
    # privileged + active -> must NOT be flagged
    az_user("u-ga-active", "cloudadmin_active", last_sign_in_days=2),
    # ordinary dormant / never used -> az-dormant-user
    az_user("u-old", "alice_cloud", last_sign_in_days=250, onprem=DSID + "-1101"),
    az_user("u-never", "temp_contractor", last_sign_in_days=None, created_days=150),
    # ordinary active -> not flagged
    az_user("u-active", "bob_cloud", last_sign_in_days=1),
    # disabled dormant -> not flagged (already disabled)
    az_user("u-disabled", "leaver", enabled=False, last_sign_in_days=500),
    # role assignments: only the three cloudadmin_* are Global Administrator
    {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": GLOBAL_ADMIN, "principalId": "u-ga-old", "directoryScopeId": "/"}},
    {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": GLOBAL_ADMIN, "principalId": "u-ga-never", "directoryScopeId": "/"}},
    {"kind": "AZRoleAssignment", "data": {"roleDefinitionId": GLOBAL_ADMIN, "principalId": "u-ga-active", "directoryScopeId": "/"}},
    # devices
    {"kind": "AZDevice", "data": {"id": "d-old", "displayName": "LAPTOP-OLD", "accountEnabled": True,
                                  "operatingSystem": "Windows", "trustType": "AzureAd",
                                  "createdDateTime": iso(800), "approximateLastSignInDateTime": iso(400)}},
    {"kind": "AZDevice", "data": {"id": "d-never", "displayName": "KIOSK-PRESTAGED", "accountEnabled": True,
                                  "operatingSystem": "Windows", "trustType": "AzureAd",
                                  "createdDateTime": iso(120)}},
    {"kind": "AZDevice", "data": {"id": "d-active", "displayName": "LAPTOP-OK", "accountEnabled": True,
                                  "operatingSystem": "Windows", "trustType": "AzureAd",
                                  "createdDateTime": iso(300), "approximateLastSignInDateTime": iso(2)}},
    # groups: empty, single-member (role assignable), and a healthy one
    {"kind": "AZGroup", "data": {"id": "g-empty", "displayName": "Project-Closed", "securityEnabled": True,
                                 "isAssignableToRole": False, "tenantId": TENANT}},
    {"kind": "AZGroup", "data": {"id": "g-single", "displayName": "AAD-Role-Holders", "securityEnabled": True,
                                 "isAssignableToRole": True, "tenantId": TENANT}},
    {"kind": "AZGroup", "data": {"id": "g-ok", "displayName": "All-Staff", "securityEnabled": True,
                                 "isAssignableToRole": False, "tenantId": TENANT}},
    {"kind": "AZGroupMember", "data": {"groupId": "g-single", "member": {"id": "u-active", "@odata.type": "#microsoft.graph.user"}}},
    {"kind": "AZGroupMember", "data": {"groupId": "g-ok", "member": {"id": "u-active", "@odata.type": "#microsoft.graph.user"}}},
    {"kind": "AZGroupMember", "data": {"groupId": "g-ok", "member": {"id": "u-old", "@odata.type": "#microsoft.graph.user"}}},
]

path = os.path.join(HERE, "corp_azure.json")
with open(path, "w", encoding="utf-8") as f:
    json.dump({"data": azure, "meta": {"methods": 0, "type": "azure", "count": len(azure), "version": 5}}, f, indent=1)
print("wrote corp_azure.json", len(azure))
print("done")
