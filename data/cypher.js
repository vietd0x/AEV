/*
 * BloodHound Cypher equivalent for each indicator, keyed by catalog id.
 *
 *   query - Cypher to run in BloodHound CE (Explore > Cypher) or Neo4j
 *
 * Conventions used throughout:
 *   - well-known SIDs are matched with ENDS WITH, because BloodHound prefixes them
 *     with the domain name (e.g. "CORP.LOCAL-S-1-5-32-544")
 *   - tier-0 = RID -512 / -518 / -519 / -544 / -548 / -549 / -551
 *   - CE also exposes n.system_tags CONTAINS 'admin_tier_0'; Legacy uses n.highvalue
 *   - timestamps are epoch seconds; swap datetime().epochseconds for a literal if your
 *     BloodHound build rejects the function
 */
window.IOE_CYPHER = {

  // ---------------- Credential access ----------------
  'kerberoast-privileged': {
    ioe: 'C-PRIV-ACCOUNTS-SPN',
    query: `// Privileged accounts exposing an SPN (tier-0 Kerberoasting)
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE u.hasspn = true AND u.enabled = true
  AND NOT u.objectid ENDS WITH '-502'
  AND (g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
       OR g.objectid ENDS WITH '-518' OR g.objectid ENDS WITH 'S-1-5-32-544')
RETURN DISTINCT u.name AS account, u.serviceprincipalnames AS spns,
       u.pwdlastset AS pwdLastSet, u.pwdneverexpires AS neverExpires
ORDER BY account`
  },
  'kerberoastable': {
    ioe: 'C-SERVICE-ACCOUNT',
    query: `// Any enabled user account with an SPN
MATCH (u:User)
WHERE u.hasspn = true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502'
RETURN u.name AS account, u.serviceprincipalnames AS spns, u.pwdlastset AS pwdLastSet
ORDER BY account`
  },
  'asrep-roastable': {
    ioe: 'C-KERBEROS-CONFIG-ACCOUNT',
    query: `// AS-REP roastable accounts (Kerberos pre-authentication disabled)
MATCH (u:User)
WHERE u.dontreqpreauth = true
RETURN u.name AS account, u.enabled AS enabled, u.pwdlastset AS pwdLastSet,
       u.admincount AS adminCount`
  },
  'shadow-credentials': {
    ioe: 'C-SHADOW-CREDENTIALS',
    query: `// Who can add key credentials (Shadow Credentials) to whom
MATCH p = (n)-[:AddKeyCredentialLink]->(t)
WHERE NOT n.objectid ENDS WITH '-512' AND NOT n.objectid ENDS WITH '-519'
  AND NOT n.objectid ENDS WITH 'S-1-5-32-544'
RETURN p LIMIT 1000`
  },
  'password-not-required': {
    ioe: 'C-PASSWORD-NOT-REQUIRED',
    query: `// Accounts exempt from the password-length policy (PASSWD_NOTREQD)
MATCH (u:User)
WHERE u.passwordnotreqd = true
RETURN u.name AS account, u.enabled AS enabled, u.pwdlastset AS pwdLastSet
ORDER BY enabled DESC, account`
  },

  // ---------------- Delegation ----------------
  'unconstrained-delegation': {
    ioe: 'C-UNCONST-DELEG',
    query: `// Unconstrained delegation on anything that is not a Domain Controller
MATCH (n)
WHERE (n:User OR n:Computer) AND n.unconstraineddelegation = true
  AND NOT n.objectid ENDS WITH '-502'
OPTIONAL MATCH (n)-[:MemberOf*1..]->(dcg:Group)
WITH n, [x IN collect(dcg) WHERE x.objectid ENDS WITH '-516'] AS dcGroups
WHERE size(dcGroups) = 0
RETURN n.name AS object, labels(n)[0] AS type, n.operatingsystem AS os, n.enabled AS enabled
ORDER BY type, object`
  },
  'constrained-delegation': {
    ioe: 'C-SERVICE-ACCOUNT',
    query: `// Constrained delegation targets and resource-based delegation (RBCD)
MATCH (n)-[r:AllowedToDelegate|AllowedToAct]->(t)
RETURN n.name AS principal, labels(n)[0] AS type, type(r) AS delegationKind,
       collect(DISTINCT t.name) AS targets, n.trustedtoauth AS protocolTransition
ORDER BY principal`
  },

  // ---------------- ACL ----------------
  'dcsync-rights': {
    ioe: 'C-ROOTOBJECTS-SD-CONSISTENCY',
    query: `// Principals that can DCSync the domain (excluding tier-0 defaults)
MATCH p = (n)-[:DCSync|GetChangesAll]->(d:Domain)
WHERE NOT n.objectid ENDS WITH '-512' AND NOT n.objectid ENDS WITH '-516'
  AND NOT n.objectid ENDS WITH '-519' AND NOT n.objectid ENDS WITH 'S-1-5-32-544'
  AND NOT n.objectid ENDS WITH '-498'
RETURN p`
  },
  'dangerous-acl-sensitive': {
    ioe: 'C-DC-ACCESS-CONSISTENCY',
    query: `// Non-tier-0 principals holding dangerous rights over a tier-0 object
MATCH (t)
WHERE t:Domain
   OR (t:Group AND (t.objectid ENDS WITH '-512' OR t.objectid ENDS WITH '-519'
                    OR t.objectid ENDS WITH '-518' OR t.objectid ENDS WITH 'S-1-5-32-544'))
   OR (t:User AND t.objectid ENDS WITH '-502')
MATCH p = (n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|AllExtendedRights|AddMember]->(t)
WHERE NOT n.objectid ENDS WITH '-512' AND NOT n.objectid ENDS WITH '-519'
  AND NOT n.objectid ENDS WITH 'S-1-5-32-544' AND NOT n.objectid ENDS WITH '-516'
RETURN p`
  },

  // ---------------- Persistence ----------------
  'sid-history-privileged': {
    ioe: 'C-ACCOUNTS-DANG-SID-HISTORY',
    query: `// Any principal inheriting privilege through SID history
MATCH p = (n)-[:HasSIDHistory]->(t)
RETURN p`
  },

  // ---------------- Hardening ----------------
  'obsolete-os': {
    ioe: 'C-OBSOLETE-SYSTEMS',
    query: `// Enabled computers running an unsupported operating system
MATCH (c:Computer)
WHERE c.enabled = true AND c.operatingsystem IS NOT NULL
  AND c.operatingsystem =~ '(?i).*(windows (2000|xp|vista|7|8)( |$)|server (2000|2003|2008|2012)).*'
RETURN c.name AS computer, c.operatingsystem AS os, c.lastlogontimestamp AS lastLogon
ORDER BY os, computer`
  },
  'protected-users-missing': {
    ioe: 'C-PROTECTED-USERS-GROUP-UNUSED',
    query: `// Privileged accounts that are NOT in the Protected Users group
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
   OR g.objectid ENDS WITH 'S-1-5-32-544'
WITH DISTINCT u
OPTIONAL MATCH (u)-[:MemberOf]->(pu:Group)
WITH u, [x IN collect(pu) WHERE x.objectid ENDS WITH '-525'] AS protected
WHERE size(protected) = 0
RETURN u.name AS privilegedAccount, u.enabled AS enabled, u.hasspn AS hasSPN
ORDER BY privilegedAccount`
  },
  'admincount-orphan': {
    ioe: 'C-ADMINCOUNT-ACCOUNT-PROPS',
    query: `// adminCount=1 but no longer a member of any privileged group
MATCH (u:User)
WHERE u.admincount = true AND NOT u.objectid ENDS WITH '-500'
  AND NOT u.objectid ENDS WITH '-502'
OPTIONAL MATCH (u)-[:MemberOf*1..]->(g:Group)
WITH u, [x IN collect(g) WHERE x.objectid ENDS WITH '-512' OR x.objectid ENDS WITH '-519'
         OR x.objectid ENDS WITH '-518' OR x.objectid ENDS WITH 'S-1-5-32-544'] AS privGroups
WHERE size(privGroups) = 0
RETURN u.name AS account, u.enabled AS enabled
ORDER BY account`
  },
  'laps-missing': {
    ioe: 'C-LAPS-UNSECURE-CONFIG',
    query: `// Enabled computers without a LAPS-managed local administrator password
MATCH (c:Computer)
WHERE c.enabled = true AND c.haslaps = false
RETURN c.name AS computer, c.operatingsystem AS os, c.lastlogontimestamp AS lastLogon
ORDER BY computer`
  },
  'machine-account-quota': {
    ioe: 'C-USERS-CAN-JOIN-COMPUTERS',
    query: `// Machine account quota (0 = only delegated accounts may join)
MATCH (d:Domain)
RETURN d.name AS domain, d.machineaccountquota AS machineAccountQuota`
  },
  'domain-functional-level': {
    ioe: 'C-DOMAIN-FUNCTIONAL-LEVEL',
    query: `// Domain functional level
MATCH (d:Domain)
RETURN d.name AS domain, d.functionallevel AS functionalLevel`
  },
  'guest-enabled': {
    ioe: 'C-GUEST-ACCOUNT',
    query: `// Built-in Guest account state
MATCH (u:User)
WHERE u.objectid ENDS WITH '-501'
RETURN u.name AS account, u.enabled AS enabled`
  },

  // ---------------- Credential hygiene ----------------
  'password-never-expires': {
    ioe: 'C-PASSWORD-DONT-EXPIRE',
    query: `// Enabled accounts whose password never expires
MATCH (u:User)
WHERE u.enabled = true AND u.pwdneverexpires = true
  AND NOT u.objectid ENDS WITH '-502'
RETURN u.name AS account, u.pwdlastset AS pwdLastSet, u.admincount AS adminCount
ORDER BY adminCount DESC, account`
  },
  'old-password': {
    ioe: 'C-USER-PASSWORD',
    query: `// Enabled accounts whose password is older than 180 days
MATCH (u:User)
WHERE u.enabled = true AND u.pwdlastset > 0
  AND u.pwdlastset < (datetime().epochseconds - (180 * 86400))
RETURN u.name AS account, u.pwdlastset AS pwdLastSet,
       (datetime().epochseconds - u.pwdlastset) / 86400 AS passwordAgeDays,
       u.admincount AS adminCount
ORDER BY passwordAgeDays DESC`
  },
  'dormant-account': {
    ioe: 'C-SLEEPING-ACCOUNTS',
    query: `// Enabled accounts with no logon for 90+ days
MATCH (u:User)
WHERE u.enabled = true AND u.lastlogontimestamp > 0
  AND u.lastlogontimestamp < (datetime().epochseconds - (90 * 86400))
RETURN u.name AS account, u.lastlogontimestamp AS lastLogon,
       (datetime().epochseconds - u.lastlogontimestamp) / 86400 AS daysInactive
ORDER BY daysInactive DESC`
  },

  // ---------------- Least privilege ----------------
  'too-many-admins': {
    ioe: 'C-NATIVE-ADM-GROUP-MEMBERS',
    query: `// Effective membership of every native administrative group
MATCH (n)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
   OR g.objectid ENDS WITH '-518' OR g.objectid ENDS WITH 'S-1-5-32-544'
   OR g.objectid ENDS WITH 'S-1-5-32-548' OR g.objectid ENDS WITH 'S-1-5-32-551'
RETURN g.name AS adminGroup, count(DISTINCT n) AS effectiveMembers,
       collect(DISTINCT n.name)[..100] AS members
ORDER BY effectiveMembers DESC`
  },
  'disabled-in-priv-group': {
    ioe: 'C-DISABLED-ACCOUNTS-PRIV-GROUPS',
    query: `// Disabled accounts still sitting in a privileged group
MATCH (n)-[:MemberOf*1..]->(g:Group)
WHERE (g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
       OR g.objectid ENDS WITH '-518' OR g.objectid ENDS WITH 'S-1-5-32-544')
  AND n.enabled = false
RETURN DISTINCT n.name AS account, labels(n)[0] AS type, g.name AS privilegedGroup`
  },

  // ---------------- ADCS ----------------
  'adcs-esc1': {
    ioe: 'C-PKI-DANG-ACCESS',
    query: `// ESC1: enrollee supplies subject + auth EKU + no approval, enrollable by low-priv
MATCH (ct:CertTemplate)
WHERE ct.enrolleesuppliessubject = true
  AND ct.authenticationenabled = true
  AND ct.requiresmanagerapproval = false
  AND coalesce(ct.authorizedsignatures, 0) = 0
MATCH (n)-[:Enroll|AllExtendedRights|GenericAll]->(ct)
WHERE NOT n.objectid ENDS WITH '-512' AND NOT n.objectid ENDS WITH '-519'
  AND NOT n.objectid ENDS WITH 'S-1-5-32-544'
RETURN DISTINCT n.name AS principal, ct.name AS template

// CE also computes this as a single edge:
//   MATCH p = (n)-[:ADCSESC1]->(d:Domain) RETURN p`
  },
  'adcs-esc2-esc3': {
    ioe: 'C-PKI-DANG-ACCESS',
    query: `// ESC2 (Any Purpose / SubCA) and ESC3 (Certificate Request Agent)
MATCH (ct:CertTemplate)
WHERE ct.requiresmanagerapproval = false
  AND (size(coalesce(ct.effectiveekus, [])) = 0
       OR '2.5.29.37.0' IN ct.effectiveekus
       OR '1.3.6.1.4.1.311.20.2.1' IN ct.effectiveekus)
MATCH (n)-[:Enroll|AllExtendedRights|GenericAll]->(ct)
WHERE NOT n.objectid ENDS WITH '-512' AND NOT n.objectid ENDS WITH '-519'
  AND NOT n.objectid ENDS WITH 'S-1-5-32-544'
RETURN DISTINCT n.name AS principal, ct.name AS template, ct.effectiveekus AS ekus`
  },
  'adcs-esc4': {
    ioe: 'C-PKI-DANG-ACCESS',
    query: `// ESC4: write access over a certificate template object
MATCH p = (n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|
               WritePKIEnrollmentFlag|WritePKINameFlag]->(ct:CertTemplate)
WHERE NOT n.objectid ENDS WITH '-512' AND NOT n.objectid ENDS WITH '-519'
  AND NOT n.objectid ENDS WITH 'S-1-5-32-544'
RETURN p`
  },
  'adcs-esc6': {
    ioe: 'C-PKI-DANG-ACCESS',
    query: `// ESC6: CA honours a requester-supplied SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)
MATCH (ca:EnterpriseCA)
WHERE ca.isuserspecifiessanenabled = true
RETURN ca.name AS certificationAuthority, ca.dnshostname AS host`
  },
  'adcs-esc7': {
    ioe: 'C-PKI-DANG-ACCESS',
    query: `// ESC7: CA management rights held by non-tier-0 principals
MATCH p = (n)-[:ManageCA|ManageCertificates]->(ca:EnterpriseCA)
WHERE NOT n.objectid ENDS WITH '-512' AND NOT n.objectid ENDS WITH '-519'
  AND NOT n.objectid ENDS WITH 'S-1-5-32-544'
RETURN p`
  },
  'adcs-esc9': {
    ioe: 'C-PKI-DANG-ACCESS',
    query: `// ESC9: authentication template without the SID security extension
MATCH (ct:CertTemplate)
WHERE ct.nosecurityextension = true AND ct.authenticationenabled = true
OPTIONAL MATCH (n)-[:Enroll]->(ct)
RETURN ct.name AS template, collect(DISTINCT n.name)[..25] AS enrollees`
  },

  // ---------------- Group policy ----------------
  'gpo-dangerous-acl': {
    ioe: 'C-GPO-SD-CONSISTENCY',
    query: `// Non-tier-0 principals able to modify a GPO (and what it is linked to)
MATCH p = (n)-[:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|WriteGPLink]->(g:GPO)
WHERE NOT n.objectid ENDS WITH '-512' AND NOT n.objectid ENDS WITH '-519'
  AND NOT n.objectid ENDS WITH 'S-1-5-32-544'
OPTIONAL MATCH (g)-[:GPLink]->(target)
RETURN n.name AS principal, g.name AS gpo, collect(DISTINCT target.name) AS linkedTo`
  },
  'gpo-unlinked-disabled': {
    ioe: 'C-GPOLICY-DISABLED-UNLINKED',
    query: `// GPOs that are not linked anywhere
MATCH (g:GPO)
WHERE NOT (g)-[:GPLink]->()
RETURN g.name AS gpo, g.gpcpath AS sysvolPath
ORDER BY gpo`
  },

  // ---------------- Trust ----------------
  'trust-sid-filtering-disabled': {
    ioe: 'C-DANGEROUS-TRUST-RELATIONSHIP',
    query: `// SID filtering disabled on a cross-forest / external trust.
// SameForestTrust is intentionally excluded: inside a forest, filtering does not apply.
MATCH (a:Domain)-[r:CrossForestTrust|TrustedBy]->(b:Domain)
WHERE r.sidfilteringenabled = false
RETURN a.name AS fromDomain, b.name AS trustedDomain, type(r) AS edge,
       r.trusttype AS trustType, r.trustdirection AS direction, r.transitive AS transitive`
  },
  'trust-tgt-delegation': {
    ioe: 'C-DANGEROUS-TRUST-RELATIONSHIP',
    query: `// TGT delegation enabled across a trust
MATCH (a:Domain)-[r:CrossForestTrust|TrustedBy]->(b:Domain)
WHERE r.tgtdelegationenabled = true
RETURN a.name AS fromDomain, b.name AS trustedDomain,
       r.trusttype AS trustType, r.trustdirection AS direction`
  },
  'trust-transitive-external': {
    ioe: 'C-DANGEROUS-TRUST-RELATIONSHIP',
    query: `// External trusts that are transitive (they should not be)
MATCH (a:Domain)-[r:CrossForestTrust|TrustedBy]->(b:Domain)
WHERE r.transitive = true AND toLower(coalesce(r.trusttype, '')) = 'external'
RETURN a.name AS fromDomain, b.name AS trustedDomain,
       r.trustdirection AS direction, r.sidfilteringenabled AS sidFiltering`
  },
  // ---------------- Hygiene and lifecycle ----------------
  'obsolete-os-privileged': {
    ioe: 'C-OBSOLETE-SYSTEMS',
    query: `// Tier-0 computers (DC or privileged group member) on an unsupported OS
MATCH (c:Computer)
WHERE c.operatingsystem IS NOT NULL
  AND c.operatingsystem =~ '(?i).*(windows (2000|xp|vista|7|8)( |$)|server (2000|2003|2008|2012)).*'
MATCH (c)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-516' OR g.objectid ENDS WITH '-512'
   OR g.objectid ENDS WITH '-519' OR g.objectid ENDS WITH 'S-1-5-32-544'
RETURN DISTINCT c.name AS computer, c.operatingsystem AS os,
       c.lastlogontimestamp AS lastLogon, c.enabled AS enabled`
  },
  'dormant-privileged-account': {
    ioe: 'C-SLEEPING-ACCOUNTS',
    query: `// Privileged accounts dormant for 90+ days, or never used
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
   OR g.objectid ENDS WITH '-518' OR g.objectid ENDS WITH 'S-1-5-32-544'
WITH DISTINCT u
WHERE u.enabled = true AND NOT u.objectid ENDS WITH '-502'
  AND (u.lastlogontimestamp IS NULL OR u.lastlogontimestamp <= 0
       OR u.lastlogontimestamp < (datetime().epochseconds - (90 * 86400)))
RETURN u.name AS privilegedAccount, u.lastlogontimestamp AS lastLogon,
       u.pwdlastset AS pwdLastSet, u.admincount AS adminCount
ORDER BY lastLogon`
  },
  'dormant-domain-controller': {
    ioe: 'C-SLEEPING-ACCOUNTS',
    query: `// Domain Controllers that have not authenticated for 45+ days
MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH '-516'
  AND c.lastlogontimestamp > 0
  AND c.lastlogontimestamp < (datetime().epochseconds - (45 * 86400))
RETURN DISTINCT c.name AS domainController, c.operatingsystem AS os,
       c.lastlogontimestamp AS lastLogon,
       (datetime().epochseconds - c.lastlogontimestamp) / 86400 AS daysInactive`
  },
  'priv-group-size': {
    ioe: 'C-UNNECESSARY-GROUP',
    query: `// Privileged groups that are empty or have a single member
MATCH (g:Group)
WHERE g.objectid ENDS WITH '-512' OR g.objectid ENDS WITH '-519'
   OR g.objectid ENDS WITH '-518' OR g.objectid ENDS WITH 'S-1-5-32-544'
   OR g.objectid ENDS WITH 'S-1-5-32-548' OR g.objectid ENDS WITH 'S-1-5-32-551'
   OR g.admincount = true
OPTIONAL MATCH (m)-[:MemberOf*1..]->(g)
WITH g, count(DISTINCT m) AS members
WHERE members <= 1
RETURN g.name AS privilegedGroup, members
ORDER BY members, privilegedGroup`
  },
  'duplicate-objects': {
    ioe: 'C-CONFLICTED-OBJECTS',
    query: `// Replication-conflict objects, and duplicated sAMAccountName values
MATCH (n)
WHERE (n:User OR n:Computer OR n:Group)
  AND (n.distinguishedname CONTAINS 'CNF:' OR n.name CONTAINS 'CNF:')
RETURN n.name AS object, labels(n)[0] AS type, n.distinguishedname AS dn, 'conflict' AS issue

UNION

MATCH (n)
WHERE (n:User OR n:Computer OR n:Group) AND n.samaccountname IS NOT NULL
WITH toLower(n.samaccountname) AS sam, collect(n.name) AS names, count(*) AS c
WHERE c > 1
RETURN head(names) AS object, 'multiple' AS type, sam AS dn, 'duplicate sAMAccountName' AS issue`
  },
  'group-size-hygiene': {
    ioe: 'C-UNNECESSARY-GROUP',
    query: `// Non-privileged groups that are empty or have a single member
MATCH (g:Group)
WHERE NOT g.objectid ENDS WITH '-513' AND NOT g.objectid ENDS WITH '-515'
  AND NOT g.objectid ENDS WITH '-512' AND NOT g.objectid ENDS WITH '-519'
  AND NOT g.objectid ENDS WITH 'S-1-5-32-544'
  AND coalesce(g.admincount, false) = false
OPTIONAL MATCH (m)-[:MemberOf]->(g)
WITH g, count(m) AS members
WHERE members <= 1
RETURN g.name AS group, members
ORDER BY members, group`
  },
  // ---------------- Entra ID (needs AzureHound data in the same database) ----
  'az-dormant-privileged-user': {
    ioe: null,
    query: `// Entra ID accounts with a privileged directory role that look unused.
// Requires AzureHound data; sign-in timestamps need AuditLog.Read.All + a premium licence.
MATCH (u:AZUser)-[:AZHasRole]->(r:AZRole)
WHERE u.enabled = true
  AND r.templateid IN [
    '62e90394-69f5-4237-9190-012177145e10', // Global Administrator
    'e8611ab8-c189-46e8-94e1-60213ab1f814', // Privileged Role Administrator
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', // Privileged Authentication Administrator
    'fe930be7-5e62-47db-91af-98c3a49a38b1', // User Administrator
    '194ae4cb-b126-40b2-bd5b-6091b380977d'  // Security Administrator
  ]
RETURN DISTINCT u.name AS account, r.displayname AS role,
       u.lastsignin AS lastSignIn, u.whencreated AS created
ORDER BY lastSignIn`
  },
  'az-dormant-user': {
    ioe: null,
    query: `// Enabled Entra ID users with no recent sign-in
MATCH (u:AZUser)
WHERE u.enabled = true
RETURN u.name AS account, u.lastsignin AS lastSignIn, u.whencreated AS created
ORDER BY lastSignIn`
  },
  'az-dormant-device': {
    ioe: null,
    query: `// Entra ID registered devices and their last sign-in
MATCH (d:AZDevice)
RETURN d.name AS device, d.operatingsystem AS os,
       d.lastsignin AS lastSignIn, d.whencreated AS created
ORDER BY lastSignIn`
  },
  'az-group-hygiene': {
    ioe: null,
    query: `// Entra ID groups that are empty or have a single member
MATCH (g:AZGroup)
OPTIONAL MATCH (m)-[:AZMemberOf]->(g)
WITH g, count(m) AS members
WHERE members <= 1
RETURN g.name AS group, members, g.isassignabletorole AS roleAssignable
ORDER BY members, group`
  },
  'trust-uncollected-domain': {
    ioe: 'C-DANGEROUS-TRUST-RELATIONSHIP',
    query: `// Trusted domains that were never collected (analysis blind spots).
// BloodHound creates a stub Domain node for them, with collected = false.
MATCH (a:Domain)-[r:SameForestTrust|CrossForestTrust|TrustedBy]->(b:Domain)
WHERE b.collected = false OR b.collected IS NULL
RETURN a.name AS fromDomain, b.name AS uncollectedDomain, type(r) AS edge,
       r.trusttype AS trustType, r.trustdirection AS direction`
  }
};
