/*
 * Indicator of Exposure catalog.
 * Static metadata for each check: severity, complexity, and the descriptive
 * text shown in the detail panel. Detection logic lives in js/checks.js,
 * matched to these entries by `id`.
 *
 * criticity 0-100 -> severity bucket:  <=25 Low, 26-50 Medium, 51-75 High, >=76 Critical
 */
window.IOE_CATALOG = [
  {
    id: 'kerberoast-privileged',
    name: 'Privileged Accounts Running Kerberos Services',
    category: 'Credential access',
    criticity: 90,
    complexity: 50,
    description: 'Highly privileged accounts that expose a Service Principal Name (SPN) can be Kerberoasted: any domain user can request a service ticket and crack it offline to recover the account password.',
    execSummary: 'A privileged account with an SPN lets an unprivileged attacker request a crackable Kerberos ticket. If the password is weak, the attacker recovers domain-admin-level credentials without touching a domain controller.',
    vulnDetail: 'When an account has one or more values in `servicePrincipalName`, any authenticated user can request a TGS for that SPN. The ticket is encrypted with the account\'s password hash, so it can be brute-forced offline (Kerberoasting). Service accounts frequently have weak, non-expiring passwords, and when the same account is also a member of a privileged group the impact is a full tier-0 compromise.',
    recommendation: 'Remove SPNs from privileged accounts. Where a privileged service account is unavoidable, use a group Managed Service Account (gMSA) or enforce a 25+ character random password and mark the account as sensitive.',
    references: [
      { name: 'MITRE ATT&CK T1558.003 Kerberoasting', url: 'https://attack.mitre.org/techniques/T1558/003/' }
    ],
    tools: ['Rubeus', 'Impacket GetUserSPNs', 'Hashcat']
  },
  {
    id: 'unconstrained-delegation',
    name: 'Dangerous Kerberos Unconstrained Delegation',
    category: 'Delegation',
    criticity: 85,
    complexity: 50,
    description: 'Non-domain-controller accounts configured for unconstrained delegation can impersonate any user that authenticates to them, including domain administrators.',
    execSummary: 'An account trusted for unconstrained delegation caches the Kerberos TGT of every user that connects to it. An attacker who controls such a host can capture a Domain Admin TGT and take over the domain.',
    vulnDetail: 'Unconstrained delegation (`TRUSTED_FOR_DELEGATION`) makes a host store forwardable TGTs of authenticating principals in memory. Coercing a Domain Controller to authenticate (e.g. PrinterBug / PetitPotam) yields a DC TGT and enables DCSync. Only Domain Controllers should hold this flag.',
    recommendation: 'Remove unconstrained delegation from every account that is not a Domain Controller. Migrate required delegation to constrained or resource-based constrained delegation, and add sensitive accounts to the Protected Users group.',
    references: [
      { name: 'MITRE ATT&CK T1558', url: 'https://attack.mitre.org/techniques/T1558/' }
    ],
    tools: ['Rubeus', 'mimikatz', 'Coercer']
  },
  {
    id: 'dcsync-rights',
    name: 'Root Objects Permissions Allowing DCSync-Like Attacks',
    category: 'ACL',
    criticity: 100,
    complexity: 50,
    description: 'Non-tier-0 principals hold replication rights on the domain head, allowing them to replicate secrets (DCSync) and extract every password hash.',
    execSummary: 'An account with GetChanges + GetChangesAll on the domain can pull the KRBTGT and every user hash without logging on to a DC. This is a single-step path to full domain compromise.',
    vulnDetail: 'The domain root object grants the extended rights "Replicating Directory Changes" and "Replicating Directory Changes All". Combined, they allow the DRSUAPI GetNCChanges call used by DCSync. Only Domain Controllers, Domain Admins and Enterprise Admins should hold them; any other grantee is a critical exposure.',
    recommendation: 'Remove the replication ACEs from all non-default principals on the domain object and audit for how they were granted. Rotate the KRBTGT password twice if abuse is suspected.',
    references: [
      { name: 'MITRE ATT&CK T1003.006 DCSync', url: 'https://attack.mitre.org/techniques/T1003/006/' }
    ],
    tools: ['mimikatz DCSync', 'Impacket secretsdump', 'BloodHound']
  },
  {
    id: 'dangerous-acl-sensitive',
    name: 'Unsafe Permissions on Tier-0 Objects',
    category: 'ACL',
    criticity: 90,
    complexity: 50,
    description: 'Non-privileged principals hold dangerous rights (GenericAll, WriteDacl, WriteOwner, Owns) over tier-0 objects such as the domain, privileged groups, or Domain Controllers.',
    execSummary: 'A dangerous ACE on a tier-0 object lets an unprivileged user rewrite its security, add themselves to Domain Admins, or take ownership — escalating to full control of Active Directory.',
    vulnDetail: 'Ownership or write-DACL/write-owner/full-control rights over the domain head, Domain Admins / Enterprise Admins / Administrators groups, the AdminSDHolder container, the KRBTGT account, or Domain Controller computer objects allow privilege escalation. These rights should be limited to the tier-0 administrative principals.',
    recommendation: 'Review and remove non-tier-0 ACEs on sensitive objects. Restore inheritance to a clean state and ensure AdminSDHolder (SDProp) protects privileged objects.',
    references: [
      { name: 'MITRE ATT&CK T1222 ACL modification', url: 'https://attack.mitre.org/techniques/T1222/' }
    ],
    tools: ['BloodHound', 'PowerSploit', 'aclpwn']
  },
  {
    id: 'shadow-credentials',
    name: 'Shadow Credentials (AddKeyCredentialLink)',
    category: 'Credential access',
    criticity: 80,
    complexity: 50,
    description: 'Non-privileged principals can write the msDS-KeyCredentialLink attribute of accounts, allowing them to add alternate certificate credentials and authenticate as the victim.',
    execSummary: 'With AddKeyCredentialLink over an account, an attacker registers their own key credential and obtains a certificate to authenticate as that account — a stealthy takeover that survives password resets.',
    vulnDetail: 'The Key Credential Link attribute backs Windows Hello for Business. A principal with GenericAll, GenericWrite, or the AddKeyCredentialLink extended right on a user or computer can add a device key and then PKINIT-authenticate as the target, recovering its NT hash.',
    recommendation: 'Remove the ability to write key credentials from untrusted principals. Deploy Windows Hello for Business key trust with proper delegation and monitor msDS-KeyCredentialLink changes.',
    references: [
      { name: 'Certified Pre-Owned / Shadow Credentials', url: 'https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab' }
    ],
    tools: ['Whisker', 'pyWhisker', 'Certipy shadow']
  },
  {
    id: 'asrep-roastable',
    name: 'Accounts Not Requiring Kerberos Pre-Authentication',
    category: 'Credential access',
    criticity: 70,
    complexity: 20,
    description: 'Accounts with Kerberos pre-authentication disabled (DONT_REQ_PREAUTH) can be AS-REP roasted: an attacker requests an AS-REP and cracks it offline without any credentials.',
    execSummary: 'Any account with pre-authentication disabled hands out a crackable AS-REP to anonymous requesters. Weak passwords on these accounts are recovered offline.',
    vulnDetail: 'When `DONT_REQUIRE_PREAUTH` is set, the KDC returns an AS-REP encrypted with the account password without proving knowledge of it. This enables offline cracking (AS-REP roasting) with no prior foothold.',
    recommendation: 'Clear the "Do not require Kerberos preauthentication" flag on all accounts. If an application requires it, enforce a long random password and restrict the account.',
    references: [
      { name: 'MITRE ATT&CK T1558.004 AS-REP Roasting', url: 'https://attack.mitre.org/techniques/T1558/004/' }
    ],
    tools: ['Rubeus', 'Impacket GetNPUsers', 'Hashcat']
  },
  {
    id: 'kerberoastable',
    name: 'Kerberoastable User Accounts',
    category: 'Credential access',
    criticity: 65,
    complexity: 50,
    description: 'Enabled user accounts exposing an SPN can be Kerberoasted by any authenticated user.',
    execSummary: 'Every user account with an SPN can be targeted for offline password cracking. Service accounts with weak passwords are a common initial foothold and lateral-movement vector.',
    vulnDetail: 'User accounts (as opposed to computer accounts) with `servicePrincipalName` populated are requestable for TGS tickets by any domain user and crackable offline. Even non-privileged service accounts often lead to further access.',
    recommendation: 'Convert service accounts to group Managed Service Accounts (gMSA), enforce 25+ character passwords, and remove unused SPNs.',
    references: [
      { name: 'MITRE ATT&CK T1558.003 Kerberoasting', url: 'https://attack.mitre.org/techniques/T1558/003/' }
    ],
    tools: ['Rubeus', 'Impacket GetUserSPNs', 'Hashcat']
  },
  {
    id: 'constrained-delegation',
    name: 'Dangerous Constrained / RBCD Delegation',
    category: 'Delegation',
    criticity: 60,
    complexity: 50,
    description: 'Accounts configured for constrained delegation (with protocol transition) or holding allowed-to-delegate targets can impersonate arbitrary users to the target services.',
    execSummary: 'Constrained delegation with protocol transition lets a compromised account impersonate any user — including administrators — to the configured services, enabling lateral movement to tier-0 systems.',
    vulnDetail: 'Accounts with `msDS-AllowedToDelegateTo` populated (especially combined with TRUSTED_TO_AUTH_FOR_DELEGATION / protocol transition) can request tickets on behalf of any principal to those SPNs. If a target service runs on a Domain Controller, this is a domain compromise path.',
    recommendation: 'Restrict delegation to the minimum required services, avoid protocol transition, and add privileged users to the Protected Users group so they cannot be delegated.',
    references: [
      { name: 'MITRE ATT&CK T1558', url: 'https://attack.mitre.org/techniques/T1558/' }
    ],
    tools: ['Rubeus', 'Impacket', 'Kekeo']
  },
  {
    id: 'sid-history-privileged',
    name: 'Accounts With a Dangerous SID History',
    category: 'Persistence',
    criticity: 70,
    complexity: 50,
    description: 'Accounts whose sIDHistory contains a privileged or foreign-domain SID silently inherit those privileges, a classic persistence and escalation technique.',
    execSummary: 'A SID History entry pointing at a privileged group grants that access invisibly, bypassing normal group-membership review. It is a common golden-ticket / persistence artifact.',
    vulnDetail: 'The `sIDHistory` attribute is honored during authorization. An attacker who can write it (e.g. via DCShadow or Mimikatz) injects the SID of Domain Admins or a foreign domain, granting privileges without appearing in any group. Legitimate use is limited to in-progress migrations.',
    recommendation: 'Audit every account with a populated sIDHistory. Remove privileged or foreign SIDs once migrations complete and enable SID filtering on trusts.',
    references: [
      { name: 'MITRE ATT&CK T1134.005 SID-History Injection', url: 'https://attack.mitre.org/techniques/T1134/005/' }
    ],
    tools: ['mimikatz', 'DSInternals']
  },
  {
    id: 'password-not-required',
    name: 'Accounts With Possible Empty Password',
    category: 'Credential hygiene',
    criticity: 70,
    complexity: 20,
    description: 'Accounts with the PASSWD_NOTREQD flag may have an empty or trivial password and can bypass the domain password policy.',
    execSummary: 'An account that does not require a password can often be accessed with no or a trivial secret, giving an attacker an easy foothold.',
    vulnDetail: 'The `PASSWD_NOTREQD` flag in userAccountControl exempts an account from the minimum-password-length policy. Such accounts may have blank passwords set administratively or via scripts, and are frequently overlooked.',
    recommendation: 'Clear the PASSWD_NOTREQD flag, set strong passwords, and disable accounts that are no longer used.',
    references: [
      { name: 'MS-DS userAccountControl flags', url: 'https://learn.microsoft.com/windows/win32/adschema/a-useraccountcontrol' }
    ],
    tools: []
  },
  {
    id: 'obsolete-os',
    name: 'Computers Running an Obsolete OS',
    category: 'Hardening',
    criticity: 70,
    complexity: 90,
    description: 'Enabled computers running an operating system no longer supported by Microsoft increase the attack surface and cannot receive security fixes.',
    execSummary: 'Unsupported operating systems (Windows 7, 2008, XP, etc.) no longer receive patches. A single unpatched host is a reliable entry point and pivot for ransomware.',
    vulnDetail: 'End-of-life Windows versions lack current security updates and modern mitigations (LSASS protection, credential guard, SMB signing defaults). They are routinely exploited via known CVEs and used for lateral movement.',
    recommendation: 'Decommission or isolate obsolete systems. Where they must remain, place them in a hardened, segmented network with restricted access and enhanced monitoring.',
    references: [
      { name: 'Microsoft product lifecycle', url: 'https://learn.microsoft.com/lifecycle/' }
    ],
    tools: []
  },
  {
    id: 'protected-users-missing',
    name: 'Privileged Users Not in Protected Users',
    category: 'Hardening',
    criticity: 55,
    complexity: 30,
    description: 'Highly privileged accounts that are not members of the Protected Users group remain exposed to credential theft techniques they could be shielded from.',
    execSummary: 'Privileged accounts outside the Protected Users group can be delegated, cached, and NTLM-relayed. Membership hardens them against several credential-theft techniques.',
    vulnDetail: 'The Protected Users group enforces stronger protections: no NTLM, no DES/RC4, no delegation, and no long-lived credential caching. Privileged (admincount) accounts left outside it stay vulnerable to Kerberoasting, delegation abuse, and pass-the-hash.',
    recommendation: 'Add tier-0 human administrators to the Protected Users group after validating application compatibility. Do not add service accounts that require delegation.',
    references: [
      { name: 'Protected Users Security Group', url: 'https://learn.microsoft.com/windows-server/security/credentials-protection-and-management/protected-users-security-group' }
    ],
    tools: []
  },
  {
    id: 'admincount-orphan',
    name: 'AdminCount Set on Standard Users',
    category: 'Hardening',
    criticity: 40,
    complexity: 20,
    description: 'Accounts carry adminCount=1 but are no longer members of a privileged group, leaving them with AdminSDHolder-protected ACLs and broken inheritance.',
    execSummary: 'A leftover adminCount flag keeps restrictive, non-inherited ACLs on accounts that are no longer privileged, complicating administration and hiding stale privilege.',
    vulnDetail: 'AdminSDHolder (SDProp) stamps adminCount=1 and a fixed ACL on members of protected groups. When an account leaves the group, the flag and ACL are not reverted, so the object keeps broken inheritance and looks privileged when it is not.',
    recommendation: 'For accounts no longer intended to be privileged, clear adminCount, re-enable inheritance, and reset the ACL to the OU default.',
    references: [
      { name: 'AdminSDHolder / SDProp', url: 'https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory' }
    ],
    tools: []
  },
  {
    id: 'password-never-expires',
    name: 'Accounts With Never-Expiring Passwords',
    category: 'Credential hygiene',
    criticity: 45,
    complexity: 50,
    description: 'Enabled accounts with DONT_EXPIRE_PASSWORD keep the same password indefinitely, bypassing renewal policy and extending the window for credential theft.',
    execSummary: 'A never-expiring password is never rotated, so a leaked or cracked credential stays valid forever. Privileged accounts with this flag are especially dangerous.',
    vulnDetail: 'The `DONT_EXPIRE_PASSWORD` flag exempts an account from the maximum-password-age policy. It is common on service accounts, but combined with a weak or exposed password it gives attackers indefinite access.',
    recommendation: 'Remove the flag where possible and rotate the password. For service accounts that need it, migrate to gMSA (automatic rotation) or enforce a long random secret with periodic manual rotation.',
    references: [],
    tools: []
  },
  {
    id: 'old-password',
    name: 'Accounts Using Old Passwords',
    category: 'Credential hygiene',
    criticity: 35,
    complexity: 40,
    description: 'Active accounts whose password has not changed in a long time increase the risk of credential theft and offline cracking.',
    execSummary: 'Passwords that have not rotated for a long time are more likely to have leaked and had more time to be cracked. Sensitive accounts should rotate on a defined cadence.',
    vulnDetail: 'Old `pwdLastSet` values indicate stale credentials. For accounts managing sensitive access, an unchanged password extends the exposure window and often coincides with weak, human-chosen secrets.',
    recommendation: 'Rotate passwords for accounts managing sensitive access on an appropriate schedule and adopt gMSA for service accounts to automate rotation.',
    references: [],
    tools: ['Hashcat', 'John the Ripper']
  },
  {
    id: 'dormant-account',
    name: 'Dormant Accounts',
    category: 'Credential hygiene',
    criticity: 35,
    complexity: 10,
    description: 'Enabled accounts that have not authenticated for a long time are unused and provide attackers with credentials that no one is watching.',
    execSummary: 'Dormant but enabled accounts are prime targets: they are not monitored, their passwords may be weak or unchanged, and their compromise is unlikely to be noticed.',
    vulnDetail: 'Accounts with a very old last-logon timestamp that remain enabled represent unmanaged access. They are frequently service or ex-employee accounts and are a common initial-access and persistence vector.',
    recommendation: 'Disable accounts that are no longer used, review them periodically, and delete them after a retention window.',
    references: [],
    tools: []
  },
  {
    id: 'laps-missing',
    name: 'Local Administrator Password Not Managed by LAPS',
    category: 'Hardening',
    criticity: 35,
    complexity: 50,
    description: 'Enabled computers without a LAPS-managed local administrator password likely share a common local admin secret, enabling lateral movement.',
    execSummary: 'Without LAPS, machines often share the same local administrator password. One cracked or dumped hash then unlocks every machine that reuses it (pass-the-hash lateral movement).',
    vulnDetail: 'LAPS randomizes and rotates each computer\'s local administrator password and stores it in AD. Computers with no LAPS attribute populated typically rely on a static, shared local admin credential — a textbook lateral-movement enabler.',
    recommendation: 'Deploy Windows LAPS to all workstations and member servers, and restrict who can read the managed passwords.',
    references: [
      { name: 'Windows LAPS', url: 'https://learn.microsoft.com/windows-server/identity/laps/laps-overview' }
    ],
    tools: ['mimikatz', 'CrackMapExec']
  },
  {
    id: 'too-many-admins',
    name: 'Too Many Members in a Privileged Group',
    category: 'Least privilege',
    criticity: 50,
    complexity: 50,
    description: 'Privileged groups (Domain Admins, Enterprise Admins, Administrators, etc.) contain more members than a least-privilege model recommends.',
    execSummary: 'A large tier-0 group means a large tier-0 attack surface: every extra admin is another account whose compromise yields full control of the domain.',
    vulnDetail: 'The more principals in Domain Admins / Enterprise Admins / Schema Admins / built-in Administrators, the more paths to domain compromise. Nested groups compound the problem by adding members that are not obvious in the direct list.',
    recommendation: 'Reduce privileged group membership to the minimum, remove nested groups, use just-in-time / just-enough administration, and keep break-glass accounts documented and monitored.',
    references: [],
    tools: []
  },
  {
    id: 'disabled-in-priv-group',
    name: 'Disabled Accounts in Privileged Groups',
    category: 'Least privilege',
    criticity: 20,
    complexity: 20,
    description: 'Disabled accounts that remain members of privileged groups regain full privilege the moment they are re-enabled, often without review.',
    execSummary: 'A disabled account in a privileged group is dormant privilege. Re-enabling it — accidentally or maliciously — instantly restores tier-0 access.',
    vulnDetail: 'Disabled accounts left in Domain Admins or similar groups are easy to overlook. An attacker who can re-enable an account (or an administrator who does so by mistake) immediately obtains its privileged group memberships.',
    recommendation: 'Remove disabled accounts from privileged groups. If they must be retained for audit, move them out of tier-0 groups first.',
    references: [],
    tools: []
  },
  {
    id: 'machine-account-quota',
    name: 'Non-Zero Machine Account Quota',
    category: 'Hardening',
    criticity: 30,
    complexity: 20,
    description: 'The domain allows unprivileged users to join computers (ms-DS-MachineAccountQuota > 0), which enables RBCD and other computer-account abuses.',
    execSummary: 'When any user can create computer accounts, attackers create a controlled machine account and abuse resource-based constrained delegation or noPac-style attacks to escalate.',
    vulnDetail: 'The default `ms-DS-MachineAccountQuota` of 10 lets every authenticated user add computer objects. Attacker-created machine accounts are a building block for RBCD takeover and several CVE chains (e.g. sAMAccountName spoofing).',
    recommendation: 'Set ms-DS-MachineAccountQuota to 0 and delegate computer-join rights explicitly to the accounts that need them.',
    references: [
      { name: 'ms-DS-MachineAccountQuota', url: 'https://learn.microsoft.com/windows/win32/adschema/a-ms-ds-machineaccountquota' }
    ],
    tools: ['Impacket addcomputer', 'Powermad']
  },
  {
    id: 'domain-functional-level',
    name: 'Outdated Domain Functional Level',
    category: 'Hardening',
    criticity: 35,
    complexity: 35,
    description: 'The domain runs at a functional level below the recommended baseline, blocking newer security features.',
    execSummary: 'An old functional level prevents modern protections (e.g. improved delegation and Kerberos features) and usually indicates legacy, unsupported Domain Controllers.',
    vulnDetail: 'A low `msDS-Behavior-Version` implies Domain Controllers running older Windows Server releases and disables newer security capabilities. It is both a symptom of legacy infrastructure and a blocker for hardening.',
    recommendation: 'Upgrade Domain Controllers and raise the domain and forest functional levels to a currently supported version.',
    references: [
      { name: 'AD functional levels', url: 'https://learn.microsoft.com/windows-server/identity/ad-ds/active-directory-functional-levels' }
    ],
    tools: []
  },
  {
    id: 'guest-enabled',
    name: 'Built-in Guest Account Enabled',
    category: 'Hardening',
    criticity: 25,
    complexity: 10,
    description: 'The built-in Guest account (RID 501) is enabled, providing anonymous-style access that should remain disabled.',
    execSummary: 'An enabled Guest account offers low-friction access and is a well-known target. It should stay disabled per security baselines.',
    vulnDetail: 'The RID-501 Guest account is disabled by default for good reason. When enabled it can be used for reconnaissance and, depending on ACLs, limited access. Security baselines require it disabled.',
    recommendation: 'Disable the built-in Guest account and confirm no resources depend on guest access.',
    references: [],
    tools: []
  },
  {
    id: 'adcs-esc1',
    name: 'Misconfigured Certificate Template (ESC1)',
    category: 'ADCS',
    criticity: 95,
    complexity: 50,
    description: 'An enabled certificate template lets the enrollee supply an arbitrary subject, has an authentication EKU, requires no manager approval, and can be enrolled by non-privileged users.',
    execSummary: 'A single ESC1 template lets any low-privileged user request a certificate as a domain administrator and authenticate as them (PKINIT). It is a direct, one-step path to full domain compromise.',
    vulnDetail: 'When a template sets `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, offers a client-authentication EKU (Client Authentication, Smart Card Logon, PKINIT, or Any Purpose), does not require manager approval or authorized signatures, and grants Enroll to a broad low-privileged group, an attacker enrolls a certificate specifying a privileged UPN and authenticates as that account.',
    recommendation: 'Disable "Supply in the request" on authentication templates, require CA manager approval or authorized signatures, and restrict enrollment to the specific principals that need it. Remove unused templates from the CA.',
    references: [
      { name: 'Certified Pre-Owned (SpecterOps)', url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
    ],
    tools: ['Certify', 'Certipy', 'ForgeCert']
  },
  {
    id: 'adcs-esc2-esc3',
    name: 'Dangerous Certificate Template EKUs (ESC2 / ESC3)',
    category: 'ADCS',
    criticity: 90,
    complexity: 50,
    description: 'A template grants the Any Purpose / SubCA EKU (ESC2) or the Certificate Request Agent EKU (ESC3) and can be enrolled by non-privileged users.',
    execSummary: 'An Any-Purpose or Enrollment-Agent template lets a low-privileged user obtain certificates usable for any purpose, or to enroll on behalf of other users — both leading to impersonation and privilege escalation.',
    vulnDetail: 'ESC2: a template with the Any Purpose EKU (or no EKU / SubCA) produces certificates valid for any use, including authentication. ESC3: a template with the Certificate Request Agent EKU allows requesting certificates on behalf of other principals. Combined with broad enrollment rights and no manager approval, either enables domain escalation.',
    recommendation: 'Remove Any Purpose / SubCA and Enrollment Agent EKUs from templates that unprivileged users can enroll, require manager approval, and tightly scope enrollment-agent capabilities.',
    references: [
      { name: 'Certified Pre-Owned (SpecterOps)', url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
    ],
    tools: ['Certify', 'Certipy']
  },
  {
    id: 'adcs-esc4',
    name: 'Vulnerable Certificate Template Access Control (ESC4)',
    category: 'ADCS',
    criticity: 90,
    complexity: 50,
    description: 'Non-privileged principals hold write access (GenericAll, WriteDacl, WriteOwner, Owns, or PKI flag writes) over a certificate template object.',
    execSummary: 'Write access over a template lets an attacker reconfigure it into a vulnerable state (e.g. ESC1) and then enroll for domain administrator — turning any template into an escalation path.',
    vulnDetail: 'A principal with ownership or write permissions over a certificate template can flip `ENROLLEE_SUPPLIES_SUBJECT`, add an authentication EKU, remove manager approval, and grant themselves Enroll. This converts ESC4 into ESC1 on demand.',
    recommendation: 'Restrict template ownership and write permissions to tier-0 PKI administrators, and audit template ACLs for non-default principals.',
    references: [
      { name: 'Certified Pre-Owned (SpecterOps)', url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
    ],
    tools: ['Certipy', 'Certify', 'BloodHound']
  },
  {
    id: 'adcs-esc6',
    name: 'CA Allows Requester-Supplied SAN (ESC6)',
    category: 'ADCS',
    criticity: 95,
    complexity: 50,
    description: 'An Enterprise CA has the EDITF_ATTRIBUTESUBJECTALTNAME2 flag set, letting any requester add an arbitrary Subject Alternative Name to any certificate.',
    execSummary: 'With this CA flag, even a benign template becomes exploitable: a low-privileged user requests a certificate with a Domain Admin UPN in the SAN and authenticates as them.',
    vulnDetail: 'The `EDITF_ATTRIBUTESUBJECTALTNAME2` CA policy flag honours a user-supplied SAN on any request. This affects every authentication-capable template the CA publishes, regardless of the template\'s own subject settings, and is a domain-wide escalation.',
    recommendation: 'Remove the flag: `certutil -config "CA" -setreg policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2` and restart the CA service. Review recently issued certificates for abuse.',
    references: [
      { name: 'Certified Pre-Owned (SpecterOps)', url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
    ],
    tools: ['Certipy', 'Certify']
  },
  {
    id: 'adcs-esc7',
    name: 'Vulnerable CA Access Control (ESC7)',
    category: 'ADCS',
    criticity: 90,
    complexity: 50,
    description: 'Non-privileged principals hold ManageCA or ManageCertificates rights on an Enterprise CA.',
    execSummary: 'ManageCA / ManageCertificates rights let an attacker enable the SAN flag, approve their own pending requests, or otherwise abuse the CA to issue privileged certificates.',
    vulnDetail: 'A principal with ManageCA can change CA configuration (including enabling EDITF_ATTRIBUTESUBJECTALTNAME2 → ESC6) and manage officer rights; ManageCertificates can approve pending requests. Either allows issuing certificates that lead to escalation.',
    recommendation: 'Limit CA administrative rights (ManageCA / ManageCertificates) to tier-0 PKI administrators and remove non-default grantees.',
    references: [
      { name: 'Certified Pre-Owned (SpecterOps)', url: 'https://posts.specterops.io/certified-pre-owned-d95910965cd2' }
    ],
    tools: ['Certipy', 'Certify']
  },
  {
    id: 'adcs-esc9',
    name: 'Certificate Template Without Security Extension (ESC9)',
    category: 'ADCS',
    criticity: 65,
    complexity: 50,
    description: 'An authentication template sets CT_FLAG_NO_SECURITY_EXTENSION, removing the SID binding and weakening certificate-to-account mapping.',
    execSummary: 'Templates without the security extension are vulnerable to weak certificate mapping abuse: combined with control over a victim\'s UPN, an attacker can authenticate as another account.',
    vulnDetail: 'The `CT_FLAG_NO_SECURITY_EXTENSION` flag omits the szOID_NTDS_CA_SECURITY_EXT extension that binds a certificate to the requester\'s SID (KB5014754). On such templates, authentication relies on weaker UPN/DNS mapping, enabling ESC9-style impersonation when an attacker can influence a target\'s identifier.',
    recommendation: 'Remove the no-security-extension flag from authentication templates and enforce strong certificate mapping (StrongCertificateBindingEnforcement) on Domain Controllers.',
    references: [
      { name: 'Certipy 4.0 — ESC9/ESC10', url: 'https://research.ifcr.dk/certipy-4-0-esc9-esc10-bloodhound-gui-new-authentication-and-request-methods-and-more-7237d88061f7' }
    ],
    tools: ['Certipy']
  },
  {
    id: 'gpo-dangerous-acl',
    name: 'Unsafe Permissions on a Group Policy Object',
    category: 'Group policy',
    criticity: 80,
    complexity: 50,
    description: 'Non-privileged principals can modify a GPO (GenericAll, WriteDacl, WriteOwner, Owns, GenericWrite, or WriteGPLink), and therefore every object the GPO applies to.',
    execSummary: 'Write access to a GPO lets an attacker push a scheduled task or script to every computer or user in its scope — a fast path to mass code execution and, if the GPO is linked high, to domain compromise.',
    vulnDetail: 'A principal able to edit a GPO or its link can deploy immediate scheduled tasks, startup scripts, or registry/user-rights changes to all linked objects. GPOs linked to the domain root or the Domain Controllers OU make this a tier-0 escalation.',
    recommendation: 'Restrict GPO edit and link rights to tier-0 administrators, review non-default ACEs on Group Policy objects, and monitor SYSVOL for unexpected policy changes.',
    references: [
      { name: 'MITRE ATT&CK T1484.001 GPO Modification', url: 'https://attack.mitre.org/techniques/T1484/001/' }
    ],
    tools: ['SharpGPOAbuse', 'pyGPOAbuse', 'BloodHound']
  },
  {
    id: 'gpo-unlinked-disabled',
    name: 'Unlinked or Orphaned Group Policy Object',
    category: 'Group policy',
    criticity: 15,
    complexity: 20,
    description: 'Group Policy objects that are not linked to any site, domain, or OU add clutter, slow RSoP computation, and can weaken policy if re-linked by mistake.',
    execSummary: 'Unlinked GPOs are dormant policy. They are easy to overlook, and accidentally re-linking one can silently override or weaken existing security settings.',
    vulnDetail: 'A GPO with no active link applies to nothing but still replicates in SYSVOL and complicates the Resultant Set of Policy. Re-enabling or re-linking it by mistake can override current security parameters and create inconsistencies.',
    recommendation: 'Review unlinked GPOs, remove those that are unnecessary, and confirm the rest contain no security-relevant settings before retaining them.',
    references: [],
    tools: []
  },
  {
    id: 'trust-sid-filtering-disabled',
    name: 'Trust Without SID Filtering',
    category: 'Trust',
    criticity: 90,
    complexity: 50,
    description: 'SID filtering (quarantine) is disabled on a cross-forest or external trust, allowing principals in the trusted domain to inject privileged SIDs and escalate into this domain.',
    execSummary: 'Without SID filtering, an administrator of the trusted domain can add your Domain Admins SID to a token via SID history and act as a domain administrator here. It effectively merges the security boundary of the two domains.',
    vulnDetail: 'SID filtering removes SIDs from another domain that do not belong to it when a token crosses the trust. When it is disabled on a `Forest` or `External` trust, an attacker controlling the trusted side sets `sIDHistory` on an account to a privileged SID of this domain and authenticates across the trust with those privileges. Note that SID filtering is intentionally not applied to intra-forest trusts (`ParentChild`, `CrossLink`), because the forest — not the domain — is the security boundary; those are therefore not reported here.',
    recommendation: 'Enable SID filtering (quarantine) on external and cross-forest trusts: `netdom trust <ThisDomain> /domain:<TrustedDomain> /quarantine:yes`. Treat any trust where it must stay off as an extension of your tier-0 boundary.',
    references: [
      { name: 'Security considerations for trusts', url: 'https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-considerations-for-trusts' },
      { name: 'MITRE ATT&CK T1134.005 SID-History Injection', url: 'https://attack.mitre.org/techniques/T1134/005/' }
    ],
    tools: ['mimikatz', 'Impacket raiseChild']
  },
  {
    id: 'trust-tgt-delegation',
    name: 'TGT Delegation Enabled Across a Trust',
    category: 'Trust',
    criticity: 70,
    complexity: 50,
    description: 'TGT delegation is enabled across a cross-forest trust, allowing unconstrained delegation hosts in the trusted forest to capture Kerberos TGTs of this domain\'s users.',
    execSummary: 'With TGT delegation on, a compromised unconstrained-delegation server in the trusted forest can collect TGTs of your users — including administrators — and replay them against your domain.',
    vulnDetail: 'By default, Windows blocks forwarding TGTs across a forest trust so that unconstrained delegation cannot be abused between forests. When `TGTDelegation` is enabled on the trust, a host with unconstrained delegation in the trusted forest receives forwardable TGTs from your principals and can reuse them, which combined with authentication coercion is a cross-forest compromise path.',
    recommendation: 'Disable TGT delegation on the trust: `netdom trust <TrustingDomain> /domain:<TrustedDomain> /EnableTGTDelegation:No`, and confirm no business process depends on cross-forest unconstrained delegation.',
    references: [
      { name: 'Updates to TGT delegation across trusts', url: 'https://support.microsoft.com/topic/updates-to-tgt-delegation-across-incoming-trusts-in-windows-server-1a6632ac-1ed5-a2b4-a0bf-e7f29b4b8e1f' }
    ],
    tools: ['Rubeus', 'mimikatz']
  },
  {
    id: 'trust-transitive-external',
    name: 'Transitive External Trust',
    category: 'Trust',
    criticity: 45,
    complexity: 35,
    description: 'An external trust is marked transitive, widening the trust beyond the two domains that were meant to be connected.',
    execSummary: 'A transitive external trust extends access to domains you never intended to trust, enlarging the attack surface and making the real trust boundary hard to reason about.',
    vulnDetail: 'External trusts are non-transitive by design: they connect exactly two domains. When transitivity is enabled, authentication can flow through the trusted domain to further domains it trusts, so compromise of any of those can reach this domain.',
    recommendation: 'Make external trusts non-transitive, or convert the relationship to a properly scoped forest trust with selective authentication and SID filtering.',
    references: [
      { name: 'Trust types and transitivity', url: 'https://learn.microsoft.com/windows-server/identity/ad-ds/plan/forest-design-models' }
    ],
    tools: []
  },
  {
    id: 'trust-uncollected-domain',
    name: 'Trust to a Domain Outside the Collection',
    category: 'Trust',
    criticity: 20,
    complexity: 20,
    description: 'An active trust points at a domain that was not collected, so no attack path into or out of it can be evaluated.',
    execSummary: 'Every uncollected trusted domain is a blind spot: principals there may hold rights in this domain, and none of it appears in the analysis.',
    vulnDetail: 'BloodHound can only reason about domains present in the dataset. An enabled trust to a domain that was not collected means any escalation path that traverses that trust is invisible, even though the trusted domain\'s administrators can generally authenticate into this one.',
    recommendation: 'Collect the trusted domains as well (`bloodhound-python` against each), or document them as accepted blind spots and verify SID filtering and selective authentication on those trusts.',
    references: [],
    tools: []
  },
  {
    id: 'obsolete-os-privileged',
    name: 'Privileged Computer Running an Obsolete OS',
    category: 'Hygiene and lifecycle',
    criticity: 85,
    complexity: 90,
    description: 'A Domain Controller or other tier-0 computer is running an operating system that is no longer supported and can no longer be patched.',
    execSummary: 'An unsupported OS on a tier-0 machine means a permanently unpatchable host holding the keys to the domain. A single public exploit is enough to take over Active Directory.',
    vulnDetail: 'Obsolete operating systems stop receiving security fixes and lack modern credential protections (Credential Guard, LSASS protection, SMB signing defaults). On a Domain Controller or a computer that is a member of a privileged group, this turns a routine patching gap into a direct domain-compromise path. Splits this by whether the machine is still active.',
    recommendation: 'Treat these as emergency: rebuild or upgrade the affected tier-0 machines onto a supported OS. If a machine must remain, isolate it on a dedicated segment with strict access control and enhanced monitoring, and remove its privileged group membership.',
    references: [
      { name: 'Microsoft product lifecycle', url: 'https://learn.microsoft.com/lifecycle/' }
    ],
    tools: []
  },
  {
    id: 'dormant-privileged-account',
    name: 'Privileged Dormant or Never-Used Account',
    category: 'Hygiene and lifecycle',
    criticity: 60,
    complexity: 20,
    description: 'A privileged account has not authenticated for a long time, or has never been used at all, yet remains enabled.',
    execSummary: 'Unused privileged accounts are the ideal target: they keep full administrative rights, nobody watches them, and their password is usually old and never rotated.',
    vulnDetail: 'A dormant tier-0 account combines high privilege with low visibility. Because no one uses it, a compromise produces no noticeable disruption and is unlikely to be spotted. Accounts that were created and never used are often provisioning leftovers or break-glass accounts whose credentials were distributed and never rotated.',
    recommendation: 'Remove the privileged group membership, disable the account, and delete it after a retention window. Genuine break-glass accounts should be documented, have their password rotated and escrowed, and be explicitly monitored for any use.',
    references: [],
    tools: []
  },
  {
    id: 'dormant-domain-controller',
    name: 'Dormant Domain Controller',
    category: 'Hygiene and lifecycle',
    criticity: 45,
    complexity: 50,
    description: 'A Domain Controller computer object has not authenticated recently, which usually means a decommissioned or offline DC whose object was never cleaned up.',
    execSummary: 'A stale Domain Controller object is a tier-0 identity nobody is watching. If the machine still exists it is an unpatched DC; if it does not, the leftover object is an escalation opportunity.',
    vulnDetail: 'Domain Controllers authenticate constantly, so an old last-logon timestamp on a DC object is abnormal. It typically indicates a DC that was removed improperly (metadata left in the directory) or one that has been powered off for a long time. The orphaned computer object retains tier-0 group membership and may still be targeted, for example via password reset or resource-based constrained delegation.',
    recommendation: 'Confirm whether the DC still exists. If it was decommissioned, clean up the metadata (`ntdsutil metadata cleanup`) and remove the computer object. If it is simply offline, bring it up to date or demote it properly.',
    references: [
      { name: 'Clean up AD DS server metadata', url: 'https://learn.microsoft.com/windows-server/identity/ad-ds/deploy/ad-ds-metadata-cleanup' }
    ],
    tools: []
  },
  {
    id: 'priv-group-size',
    name: 'Empty or Single-Member Privileged Group',
    category: 'Hygiene and lifecycle',
    criticity: 40,
    complexity: 20,
    description: 'A privileged group has no members, or exactly one, which makes the delegation model harder to reason about and leaves unused privilege in place.',
    execSummary: 'An empty privileged group is unused privilege waiting to be filled; a single-member group hides a direct grant behind an extra layer. Both make it harder to see who really holds administrative rights.',
    vulnDetail: 'Empty privileged groups still carry their rights: anyone who can add members (see the ACL indicators) gains that privilege silently, and the group is unlikely to be reviewed because it appears unused. Single-member groups add indirection without adding value, and accumulate over time until nobody can state confidently who is an administrator. Note that a deliberately minimal tier-0 group may legitimately have one member.',
    recommendation: 'Remove privileged groups that are no longer needed. Where a single-member group exists for a reason, document that reason; otherwise grant the right directly or consolidate into an existing group.',
    references: [],
    tools: []
  },
  {
    id: 'duplicate-objects',
    name: 'Duplicate or Conflicting Security Principals',
    category: 'Hygiene and lifecycle',
    criticity: 20,
    complexity: 50,
    description: 'Objects share a sAMAccountName, or carry a replication-conflict marker (CNF:), which creates ambiguity about which principal a right actually applies to.',
    execSummary: 'Duplicate or conflicted principals make it unclear which account a permission grants. Attackers use that ambiguity to hide, and administrators use it to make mistakes.',
    vulnDetail: 'Replication conflicts leave objects with a `CNF:` marker in their distinguished name. Duplicate sAMAccountName values across objects (including between users and computers) create confusion during authentication and auditing, and conflicted objects may retain group memberships and ACEs that nobody reviews because the object looks like a duplicate of something legitimate.',
    recommendation: 'Review conflicted (CNF:) objects and delete the stale copy after confirming which is authoritative. Resolve duplicate sAMAccountName values by renaming, and investigate the replication issue that produced the conflict.',
    references: [],
    tools: []
  },
  {
    id: 'group-size-hygiene',
    name: 'Empty or Single-Member Group',
    category: 'Hygiene and lifecycle',
    criticity: 15,
    complexity: 50,
    description: 'Non-privileged groups that are empty or contain a single member add directory clutter and slow down access reviews.',
    execSummary: 'Unused groups accumulate until access reviews become impractical. Individually harmless, collectively they hide the groups that actually matter.',
    vulnDetail: 'Empty and single-member groups are usually leftovers from decommissioned projects or one-off delegations. They still appear in access reviews, token computations and RSoP, and they make it harder to spot the groups that genuinely grant access.',
    recommendation: 'Review and remove groups that are no longer used. For single-member groups, either document the intent or grant the access directly.',
    references: [],
    tools: []
  },
  {
    id: 'az-dormant-privileged-user',
    name: 'Entra ID: Dormant or Never-Used Privileged User',
    category: 'Entra ID',
    criticity: 60,
    complexity: 20,
    description: 'An Entra ID account holding a privileged directory role has not signed in for a long time, or has never signed in, yet remains enabled.',
    execSummary: 'An unused cloud administrator is a standing takeover opportunity: full tenant privilege, no one watching it, and often a password that was set once and never rotated or MFA-registered.',
    vulnDetail: 'Privileged Entra ID roles (Global Administrator, Privileged Role Administrator, User Administrator and similar) grant control over the tenant and, in a hybrid environment, a path back into on-premises Active Directory. A dormant holder of such a role produces no day-to-day activity, so its compromise is unlikely to be noticed, and accounts that never signed in may still carry their initial password with no MFA registered.',
    recommendation: 'Remove the role assignment, or disable and delete the account. Where the account is a break-glass identity, document it, exclude it deliberately from Conditional Access, rotate and escrow its credential, and alert on every sign-in.',
    references: [
      { name: 'Entra ID privileged roles', url: 'https://learn.microsoft.com/entra/identity/role-based-access-control/permissions-reference' },
      { name: 'Secure emergency access accounts', url: 'https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access' }
    ],
    tools: []
  },
  {
    id: 'az-dormant-user',
    name: 'Entra ID: Dormant or Never-Used User',
    category: 'Entra ID',
    criticity: 35,
    complexity: 10,
    description: 'An enabled Entra ID user account has not signed in for a long time, or has never signed in at all.',
    execSummary: 'Dormant cloud accounts widen the attack surface for password spraying and token theft while nobody is monitoring them. Never-used accounts may still hold their initial password.',
    vulnDetail: 'Unused but enabled accounts remain valid authentication targets. They are frequently leavers, contractors, or provisioning leftovers, and are prime candidates for password spraying because failed or successful sign-ins attract no attention from the account owner.',
    recommendation: 'Disable accounts that are no longer used and delete them after a retention window. Automate the joiner/mover/leaver process and run periodic access reviews with Entra ID Identity Governance.',
    references: [],
    tools: []
  },
  {
    id: 'az-dormant-device',
    name: 'Entra ID: Dormant or Never-Used Device',
    category: 'Entra ID',
    criticity: 25,
    complexity: 20,
    description: 'A device registered in Entra ID has not signed in for a long time, or has never signed in since it was created.',
    execSummary: 'Stale device objects keep a trusted identity in the tenant for hardware that may no longer be managed, patched, or even in the company\'s possession.',
    vulnDetail: 'Registered devices are identities: they can satisfy device-based Conditional Access and hold Primary Refresh Tokens. A dormant device is typically decommissioned hardware whose object was never cleaned up, so it is neither patched nor monitored while still being trusted by policy. Pre-created device objects that never signed in indicate a provisioning process that leaves unused trust behind.',
    recommendation: 'Review and delete stale device objects on a schedule, and enforce device compliance in Conditional Access so that unmanaged or non-compliant devices cannot satisfy policy.',
    references: [
      { name: 'Manage stale devices in Entra ID', url: 'https://learn.microsoft.com/entra/identity/devices/manage-stale-devices' }
    ],
    tools: []
  },
  {
    id: 'az-group-hygiene',
    name: 'Entra ID: Empty or Single-Member Group',
    category: 'Entra ID',
    criticity: 15,
    complexity: 50,
    description: 'Entra ID groups that contain no members, or exactly one, add clutter and make access reviews harder.',
    execSummary: 'Unused groups accumulate until nobody can tell which ones actually grant access. If such a group is role-assignable, it is also unused privilege waiting to be filled.',
    vulnDetail: 'Empty and single-member groups are usually leftovers from decommissioned projects or one-off delegations, yet they still appear in access reviews, app assignments and Conditional Access scoping. A group marked `isAssignableToRole` deserves particular attention: anyone able to add members to it inherits whatever directory role it carries.',
    recommendation: 'Remove groups that are no longer used, and document the intent of deliberate single-member groups. Pay particular attention to role-assignable groups and restrict who can manage their membership.',
    references: [],
    tools: []
  }
];
