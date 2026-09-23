/*
 * BloodHound CE (v5/v6) parser + normalizer.
 * Turns the raw *_users.json / *_computers.json / ... files produced by
 * bloodhound-python into a single normalized context object used by the checks.
 *
 * Everything runs in the browser; nothing is uploaded.
 */
(function () {
  'use strict';

  var DAY = 86400; // seconds

  // ---- helpers -------------------------------------------------------------

  // Object property keys in BloodHound are lower-cased already, but be defensive.
  function props(o) { return (o && o.Properties) || {}; }

  function lc(s) { return (s == null ? '' : String(s)).toLowerCase(); }

  // Normalize a BloodHound timestamp. BH uses epoch seconds; -1 / 0 mean "never".
  function ts(v) {
    if (v == null) return null;
    var n = Number(v);
    if (!isFinite(n) || n <= 0) return null;
    // Some exports use epoch milliseconds; fold those down to seconds.
    if (n > 1e12) n = Math.floor(n / 1000);
    return n;
  }

  function ridOf(sid) {
    if (!sid) return null;
    var m = /-(\d+)$/.exec(sid);
    return m ? parseInt(m[1], 10) : null;
  }

  function isBuiltinAdministrators(sid) { return sid === 'S-1-5-32-544'; }

  // Trust enums are strings in BloodHound CE but integers in older collectors.
  var TRUST_DIRECTION = ['Disabled', 'Inbound', 'Outbound', 'Bidirectional'];
  var TRUST_TYPE = ['ParentChild', 'CrossLink', 'Forest', 'External', 'Unknown'];

  function trustEnum(v, table) {
    if (typeof v === 'number') return table[v] || String(v);
    if (typeof v === 'string' && /^\d+$/.test(v)) return table[Number(v)] || v;
    return v ? String(v) : 'Unknown';
  }
  function firstDefined(a, b) { return a !== undefined ? a : b; }

  // ---- file classification -------------------------------------------------

  // Return the collection type of a parsed BloodHound file, or null.
  function fileType(json) {
    if (!json || typeof json !== 'object') return null;
    var t = json.meta && json.meta.type;
    // AzureHound: one file, every entry tagged with an AZ* kind.
    var d0 = json.data && json.data[0];
    if (lc(t) === 'azure' || (d0 && typeof d0.kind === 'string' && /^AZ/i.test(d0.kind))) return 'azure';
    if (t) return lc(t);
    // Fallback: infer from the first data element.
    var d = json.data && json.data[0];
    if (!d) return null;
    if (d.Members) return 'groups';
    if (d.Properties && d.Properties.operatingsystem !== undefined) return 'computers';
    if (d.Trusts || (d.Properties && d.Properties.functionallevel !== undefined)) return 'domains';
    if (d.Properties && d.Properties.samaccountname !== undefined) return 'users';
    return null;
  }

  var KNOWN_TYPES = {
    users: 'User', computers: 'Computer', groups: 'Group', domains: 'Domain',
    gpos: 'GPO', ous: 'OU', containers: 'Container',
    certtemplates: 'CertTemplate', cas: 'CA', enterprisecas: 'EnterpriseCA',
    rootcas: 'RootCA', ntauthstores: 'NTAuthStore', aiacas: 'AIACA',
    issuancepolicies: 'IssuancePolicy'
  };

  // ---- Entra ID (AzureHound) ----------------------------------------------

  // Directory role template ids that grant tier-0-equivalent control in Entra ID.
  var AZ_PRIVILEGED_ROLES = {
    '62e90394-69f5-4237-9190-012177145e10': 'Global Administrator',
    'e8611ab8-c189-46e8-94e1-60213ab1f814': 'Privileged Role Administrator',
    '7be44c8a-adaf-4e2a-84d6-ab2649e08a13': 'Privileged Authentication Administrator',
    'fe930be7-5e62-47db-91af-98c3a49a38b1': 'User Administrator',
    '194ae4cb-b126-40b2-bd5b-6091b380977d': 'Security Administrator',
    '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3': 'Application Administrator',
    '158c047a-c907-4556-b7ef-446551a6b5f7': 'Cloud Application Administrator',
    'c4e39bd9-1100-46d3-8c65-fb160da0071f': 'Authentication Administrator',
    '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2': 'Hybrid Identity Administrator',
    '29232cdf-9323-42fd-ade2-1d097af3e4de': 'Exchange Administrator',
    'f28a1f50-f6e7-4571-818b-6a12f2af6b6c': 'SharePoint Administrator',
    '3a2c62db-5318-420d-8d74-23affee5d9d5': 'Intune Administrator',
    '729827e3-9c14-49f7-bb1b-9608f156bbb8': 'Helpdesk Administrator'
  };

  // Graph timestamps are ISO strings; turn them into epoch seconds.
  function isoTs(v) {
    if (!v) return null;
    if (typeof v === 'number') return ts(v);
    var n = Date.parse(v);
    return isFinite(n) ? Math.floor(n / 1000) : null;
  }

  function azSignIn(o) {
    var sa = o.signInActivity || {};
    return isoTs(sa.lastSignInDateTime) || isoTs(sa.lastNonInteractiveSignInDateTime) ||
      isoTs(o.lastSignInDateTime) || isoTs(o.approximateLastSignInDateTime) || null;
  }

  function ingestAzure(ctx, data) {
    var az = ctx.az;
    az.present = true;
    data.forEach(function (entry) {
      var kind = String(entry.kind || '');
      var o = entry.data || {};
      var k = kind.toUpperCase();
      if (k === 'AZUSER') {
        az.users.push({
          id: o.id, name: o.displayName || o.userPrincipalName || o.id,
          upn: o.userPrincipalName || '', enabled: o.accountEnabled !== false,
          created: isoTs(o.createdDateTime), lastSignIn: azSignIn(o),
          onPremSid: o.onPremisesSecurityIdentifier || null, raw: o
        });
      } else if (k === 'AZGROUP') {
        az.groups.push({
          id: o.id, name: o.displayName || o.id,
          roleAssignable: o.isAssignableToRole === true,
          securityEnabled: o.securityEnabled !== false, raw: o
        });
      } else if (k === 'AZDEVICE') {
        az.devices.push({
          id: o.id, name: o.displayName || o.id, enabled: o.accountEnabled !== false,
          os: o.operatingSystem || '', trustType: o.trustType || '',
          created: isoTs(o.createdDateTime), lastSignIn: azSignIn(o), raw: o
        });
      } else if (k === 'AZGROUPMEMBER' || k === 'AZGROUPMEMBERS') {
        var gid = o.groupId || o.GroupId;
        var m = o.member || o.Member || {};
        var mid = m.id || o.memberId;
        if (gid && mid) {
          var set = az.members.get(gid) || new Set();
          set.add(mid); az.members.set(gid, set);
        }
      } else if (k.indexOf('ROLEASSIGNMENT') >= 0) {
        var role = lc(o.roleDefinitionId || o.roleTemplateId || o.roleId || '');
        var pid = o.principalId || o.PrincipalId || (o.principal && o.principal.id);
        if (pid && AZ_PRIVILEGED_ROLES[role]) {
          az.privileged.set(pid, AZ_PRIVILEGED_ROLES[role]);
        }
      }
    });
  }

  // Resolve group membership so a user holding a role through a role-assignable
  // group is still counted as privileged.
  function expandAzPrivilege(az) {
    var changed = true, guard = 0;
    while (changed && guard++ < 50) {
      changed = false;
      az.privileged.forEach(function (roleName, pid) {
        var members = az.members.get(pid);
        if (!members) return;
        members.forEach(function (mid) {
          if (!az.privileged.has(mid)) { az.privileged.set(mid, roleName + ' (via group)'); changed = true; }
        });
      });
    }
    az.hasSignInData = az.users.some(function (u) { return u.lastSignIn; }) ||
      az.devices.some(function (d) { return d.lastSignIn; });
  }

  // ---- main normalize ------------------------------------------------------

  // files: array of { name, json } already parsed.
  function normalize(files) {
    var ctx = {
      byType: {}, bySid: new Map(), all: [],
      memberships: new Map(), // groupSid -> Set(memberSid) direct
      memberOf: new Map(),    // memberSid -> Set(groupSid) direct
      domains: [], domainSid: null, domainName: null,
      privilegedGroupSids: new Set(),
      privilegedSids: new Set(),
      protectedUsersSid: null,
      referenceNow: 0,
      warnings: [], fileSummary: [],
      az: {
        present: false, users: [], groups: [], devices: [],
        members: new Map(), privileged: new Map(), hasSignInData: false
      }
    };
    Object.keys(KNOWN_TYPES).forEach(function (k) { ctx.byType[k] = []; });

    var maxTs = 0;

    files.forEach(function (f) {
      var t = fileType(f.json);
      if (!t) { ctx.warnings.push('Skipped ' + f.name + ' (unrecognized BloodHound file).'); return; }
      var data = (f.json.data || []);
      if (!ctx.byType[t]) ctx.byType[t] = [];
      ctx.fileSummary.push({ name: f.name, type: t, count: data.length, version: f.json.meta && f.json.meta.version });

      if (t === 'azure') { ingestAzure(ctx, data); return; } // AzureHound, not the AD graph

      data.forEach(function (raw) {
        var p = props(raw);
        var node = {
          type: t,
          typeLabel: KNOWN_TYPES[t] || t,
          sid: raw.ObjectIdentifier || p.objectid || null,
          name: p.name || p.distinguishedname || raw.ObjectIdentifier || '(unknown)',
          dn: p.distinguishedname || '',
          domain: p.domain || '',
          props: p,
          aces: raw.Aces || [],
          members: raw.Members || null,
          allowedToDelegate: raw.AllowedToDelegate || [],
          raw: raw
        };
        ctx.all.push(node);
        if (node.sid) ctx.bySid.set(node.sid, node);
        ctx.byType[t].push(node);

        // Track the newest timestamp we see to use as "reference now".
        ['lastlogon', 'lastlogontimestamp', 'pwdlastset', 'whencreated'].forEach(function (k) {
          var v = ts(p[k]); if (v && v > maxTs) maxTs = v;
        });
      });
    });

    // Reference "now": newest signal in the data, or wall clock if data looks current.
    var wall = Math.floor(Date.now() / 1000);
    ctx.referenceNow = maxTs > 0 ? Math.max(maxTs, 0) : wall;
    // If the data is recent (within ~30 days of wall clock) prefer the wall clock.
    if (wall - ctx.referenceNow < 30 * DAY) ctx.referenceNow = wall;

    // Primary domain.
    ctx.domains = ctx.byType.domains || [];
    if (ctx.domains.length) {
      var dom = ctx.domains[0];
      ctx.domainSid = dom.sid;
      ctx.domainName = (dom.props.name || dom.name || '').toUpperCase();
    } else {
      // Derive from any object SID (S-1-5-21-a-b-c-RID).
      for (var i = 0; i < ctx.all.length; i++) {
        var s = ctx.all[i].sid || '';
        var m = /^(S-1-5-21-\d+-\d+-\d+)-\d+$/.exec(s);
        if (m) { ctx.domainSid = m[1]; break; }
      }
      ctx.domainName = (ctx.byType.users[0] && ctx.byType.users[0].domain || 'UNKNOWN DOMAIN').toUpperCase();
    }

    expandAzPrivilege(ctx.az);

    // Trust relationships, flattened from every collected domain.
    ctx.trusts = [];
    (ctx.byType.domains || []).forEach(function (d) {
      ((d.raw && d.raw.Trusts) || []).forEach(function (t) {
        ctx.trusts.push({
          sourceName: (d.props.name || d.name || '').toUpperCase(),
          sourceSid: d.sid,
          targetName: String(t.TargetDomainName || t.TargetDomainSid || '(unknown)').toUpperCase(),
          targetSid: t.TargetDomainSid || null,
          direction: trustEnum(t.TrustDirection, TRUST_DIRECTION),
          type: trustEnum(t.TrustType, TRUST_TYPE),
          transitive: firstDefined(t.IsTransitive, t.Transitive) === true,
          // undefined (not collected) must stay distinct from false (explicitly disabled)
          sidFiltering: firstDefined(t.SidFilteringEnabled, t.SidFiltering),
          tgtDelegation: firstDefined(t.TGTDelegationEnabled, t.TGTDelegation),
          raw: t
        });
      });
    });

    // Group memberships (direct).
    (ctx.byType.groups || []).forEach(function (g) {
      if (!g.sid || !g.members) return;
      var set = ctx.memberships.get(g.sid) || new Set();
      g.members.forEach(function (m) {
        var msid = m.ObjectIdentifier || m.objectid;
        if (!msid) return;
        set.add(msid);
        var mo = ctx.memberOf.get(msid) || new Set();
        mo.add(g.sid); ctx.memberOf.set(msid, mo);
      });
      ctx.memberships.set(g.sid, set);
    });

    // Identify well-known privileged groups and compute the transitive closure
    // of everything that is effectively a member of one.
    var dsid = ctx.domainSid;
    var seeds = [];
    if (dsid) {
      [512 /*Domain Admins*/, 519 /*Enterprise Admins*/, 518 /*Schema Admins*/,
       548 /*Account Operators*/, 549 /*Server Operators*/, 551 /*Backup Operators*/,
       550 /*Print Operators*/, 517 /*Cert Publishers*/].forEach(function (rid) {
        seeds.push(dsid + '-' + rid);
      });
      ctx.protectedUsersSid = dsid + '-525';
    }
    seeds.push('S-1-5-32-544'); // BUILTIN\Administrators
    // Also treat any group named like a tier-0 group as a seed.
    (ctx.byType.groups || []).forEach(function (g) {
      var n = lc(g.props.name);
      if (/(^|@|\\)(domain admins|enterprise admins|schema admins|administrators|account operators|backup operators|server operators|dnsadmins|key admins|enterprise key admins)@?/.test(n)) {
        seeds.push(g.sid);
      }
    });

    seeds.forEach(function (s) { if (s && ctx.bySid.has(s)) ctx.privilegedGroupSids.add(s); });

    // Transitive closure: BFS over memberships from each seed group.
    ctx.privilegedGroupSids.forEach(function (gsid) { ctx.privilegedSids.add(gsid); });
    var queue = Array.from(ctx.privilegedGroupSids);
    var guard = 0;
    while (queue.length && guard++ < 100000) {
      var cur = queue.shift();
      var mem = ctx.memberships.get(cur);
      if (!mem) continue;
      mem.forEach(function (msid) {
        if (!ctx.privilegedSids.has(msid)) {
          ctx.privilegedSids.add(msid);
          // If the member is itself a group, keep expanding.
          if (ctx.memberships.has(msid)) queue.push(msid);
        }
      });
    }

    return ctx;
  }

  // Effective (transitive) members of a group SID, resolved to nodes.
  function effectiveMembers(ctx, groupSid) {
    var out = new Map(); // sid -> node
    var seen = new Set();
    var queue = [groupSid];
    var guard = 0;
    while (queue.length && guard++ < 100000) {
      var cur = queue.shift();
      var mem = ctx.memberships.get(cur);
      if (!mem) continue;
      mem.forEach(function (msid) {
        if (seen.has(msid)) return;
        seen.add(msid);
        var node = ctx.bySid.get(msid);
        if (node) out.set(msid, node);
        if (ctx.memberships.has(msid)) queue.push(msid); // nested group
      });
    }
    return out;
  }

  window.BH = {
    normalize: normalize,
    effectiveMembers: effectiveMembers,
    ts: ts,
    ridOf: ridOf,
    isBuiltinAdministrators: isBuiltinAdministrators,
    DAY: DAY,
    fileType: fileType
  };
})();
