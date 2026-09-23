/*
 * Detection functions, one per catalog id. Each takes the normalized ctx
 * (see js/bloodhound.js) and returns an array of "deviant" objects:
 *
 *   { sid, name, type, dn, reasons: [string], attrs: { label: value } }
 *
 * Only defensive read-only analysis of the provided JSON is performed.
 */
(function () {
  'use strict';

  var DAY = 86400;
  var OLD_PWD_DAYS = 180;
  var DORMANT_DAYS = 90;

  function ts(v) { return window.BH.ts(v); }
  function rid(s) { return window.BH.ridOf(s); }

  function fmtTs(v) {
    var t = ts(v);
    if (!t) return 'never';
    try { return new Date(t * 1000).toISOString().slice(0, 10); } catch (e) { return String(v); }
  }
  function days(now, v) {
    var t = ts(v); if (!t) return null;
    return Math.floor((now - t) / DAY);
  }
  function nameOf(ctx, sid) {
    var n = ctx.bySid.get(sid);
    return n ? n.name : (sid || '(unknown)');
  }
  function enabled(p) { return p.enabled !== false; } // default true if absent

  // Well-known / default principals we never flag as illegitimate grantees.
  function isDefaultPrincipal(ctx, sid) {
    if (!sid) return true;
    if (ctx.privilegedSids.has(sid)) return true;
    var fixed = { 'S-1-5-18': 1, 'S-1-5-32-544': 1, 'S-1-5-9': 1, 'S-1-3-0': 1, 'S-1-5-10': 1, 'S-1-5-32-548': 1, 'S-1-5-32-549': 1, 'S-1-5-32-551': 1 };
    if (fixed[sid]) return true;
    var r = rid(sid);
    if ([512, 516, 518, 519, 500, 498, 502, 517].indexOf(r) >= 0) return true;
    return false;
  }

  // Domain Controllers = effective members of the -516 group, plus obvious DCs.
  function dcSids(ctx) {
    var set = new Set();
    if (ctx.domainSid) {
      var mem = window.BH.effectiveMembers(ctx, ctx.domainSid + '-516');
      mem.forEach(function (_n, sid) { set.add(sid); });
    }
    return set;
  }

  function sidHistoryOf(node) {
    var out = [];
    var p = node.props || {};
    if (Array.isArray(p.sidhistory)) p.sidhistory.forEach(function (s) { out.push(typeof s === 'string' ? s : (s && s.ObjectIdentifier)); });
    if (Array.isArray(node.raw && node.raw.HasSIDHistory)) node.raw.HasSIDHistory.forEach(function (s) { out.push(s.ObjectIdentifier || s); });
    return out.filter(Boolean);
  }

  // ---- ADCS helpers --------------------------------------------------------
  var EKU = {
    CLIENT_AUTH: '1.3.6.1.5.5.7.3.2',
    SMARTCARD_LOGON: '1.3.6.1.4.1.311.20.2.2',
    PKINIT_CLIENT: '1.3.6.1.5.2.3.4',
    ANY_PURPOSE: '2.5.29.37.0',
    ENROLLMENT_AGENT: '1.3.6.1.4.1.311.20.2.1'
  };
  function ekusOf(p) {
    var e = p.effectiveekus || p.ekus || p.certificateapplicationpolicy || [];
    return Array.isArray(e) ? e.map(String) : [];
  }
  function hasAuthEku(p) {
    if (p.authenticationenabled === true) return true;
    var e = ekusOf(p);
    if (e.length === 0) return true; // no EKU restriction => usable for auth
    return e.indexOf(EKU.CLIENT_AUTH) >= 0 || e.indexOf(EKU.SMARTCARD_LOGON) >= 0 ||
      e.indexOf(EKU.PKINIT_CLIENT) >= 0 || e.indexOf(EKU.ANY_PURPOSE) >= 0;
  }
  function isAnyPurpose(p) { var e = ekusOf(p); return e.length === 0 || e.indexOf(EKU.ANY_PURPOSE) >= 0; }
  function isEnrollmentAgent(p) { return p.enrollmentagent === true || ekusOf(p).indexOf(EKU.ENROLLMENT_AGENT) >= 0; }
  function suppliesSubject(p) { return p.enrolleesuppliessubject === true; }
  function requiresApproval(p) {
    return p.requiresmanagerapproval === true || p.enrollmentflag_pend_all_requests === true;
  }
  function authorizedSignatures(p) {
    var v = p.authorizedsignatures;
    if (v === undefined) v = p.authorizedsignaturerequired;
    var n = Number(v);
    return isFinite(n) ? n : 0;
  }
  var ENROLL_RIGHTS = { 'Enroll': 1, 'AutoEnroll': 1, 'AllExtendedRights': 1, 'GenericAll': 1 };
  // Non-privileged principals that can enroll on this template.
  function lowPrivEnrollers(ctx, node) {
    var out = [];
    (node.aces || []).forEach(function (a) {
      if (ENROLL_RIGHTS[a.RightName] && !isDefaultPrincipal(ctx, a.PrincipalSID)) out.push(a.PrincipalSID);
    });
    return out;
  }
  function enterpriseCAs(ctx) { return (ctx.byType.enterprisecas || []).concat(ctx.byType.cas || []); }

  var CHECKS = {};

  // ---- Credential access ---------------------------------------------------

  function isKerberoastable(n) {
    var p = n.props;
    if (n.type !== 'users') return false;
    if (!enabled(p)) return false;
    if (rid(n.sid) === 502) return false; // krbtgt
    var spn = p.serviceprincipalnames;
    return p.hasspn === true || (Array.isArray(spn) && spn.length > 0);
  }

  CHECKS['kerberoast-privileged'] = function (ctx) {
    return ctx.byType.users.filter(function (n) {
      return isKerberoastable(n) && (ctx.privilegedSids.has(n.sid) || n.props.admincount === true);
    }).map(function (n) {
      return dev(n, ['Privileged account exposes a Service Principal Name'], {
        SPNs: (n.props.serviceprincipalnames || []).join(', '),
        'Password last set': fmtTs(n.props.pwdlastset),
        Privileged: ctx.privilegedSids.has(n.sid) ? 'yes (group)' : 'adminCount=1'
      });
    });
  };

  CHECKS['kerberoastable'] = function (ctx) {
    return ctx.byType.users.filter(function (n) {
      return isKerberoastable(n) && !(ctx.privilegedSids.has(n.sid) || n.props.admincount === true);
    }).map(function (n) {
      return dev(n, ['Enabled user account exposes a Service Principal Name'], {
        SPNs: (n.props.serviceprincipalnames || []).join(', '),
        'Password last set': fmtTs(n.props.pwdlastset)
      });
    });
  };

  CHECKS['asrep-roastable'] = function (ctx) {
    return ctx.byType.users.filter(function (n) {
      return enabled(n.props) && n.props.dontreqpreauth === true;
    }).map(function (n) {
      return dev(n, ['Kerberos pre-authentication is not required (DONT_REQ_PREAUTH)'], {
        'Password last set': fmtTs(n.props.pwdlastset), adminCount: !!n.props.admincount
      });
    });
  };

  CHECKS['shadow-credentials'] = function (ctx) {
    var out = [];
    ['users', 'computers'].forEach(function (t) {
      ctx.byType[t].forEach(function (n) {
        var bad = (n.aces || []).filter(function (a) {
          return a.RightName === 'AddKeyCredentialLink' && !isDefaultPrincipal(ctx, a.PrincipalSID);
        });
        if (bad.length) {
          out.push(dev(n, bad.map(function (a) {
            return 'AddKeyCredentialLink granted to ' + nameOf(ctx, a.PrincipalSID);
          }), { Object: n.typeLabel }));
        }
      });
    });
    return out;
  };

  CHECKS['password-not-required'] = function (ctx) {
    return ctx.byType.users.filter(function (n) { return n.props.passwordnotreqd === true; })
      .map(function (n) { return dev(n, ['PASSWD_NOTREQD flag set (password may be empty)'], { Enabled: enabled(n.props) }); });
  };

  // ---- Delegation ----------------------------------------------------------

  CHECKS['unconstrained-delegation'] = function (ctx) {
    var dcs = dcSids(ctx);
    return ctx.all.filter(function (n) {
      return (n.type === 'users' || n.type === 'computers') &&
        n.props.unconstraineddelegation === true && !dcs.has(n.sid) && rid(n.sid) !== 502;
    }).map(function (n) {
      return dev(n, ['Trusted for unconstrained delegation and is not a Domain Controller'], {
        Type: n.typeLabel, OS: n.props.operatingsystem || '', Enabled: enabled(n.props)
      });
    });
  };

  CHECKS['constrained-delegation'] = function (ctx) {
    var dcs = dcSids(ctx);
    return ctx.all.filter(function (n) {
      if (n.type !== 'users' && n.type !== 'computers') return false;
      if (dcs.has(n.sid)) return false;
      var atd = (n.allowedToDelegate || []).length > 0;
      return atd || n.props.trustedtoauth === true;
    }).map(function (n) {
      var reasons = [];
      if (n.props.trustedtoauth === true) reasons.push('Configured for protocol transition (TRUSTED_TO_AUTH_FOR_DELEGATION)');
      if ((n.allowedToDelegate || []).length) reasons.push('Constrained delegation targets: ' + n.allowedToDelegate.map(function (x) { return x.ObjectIdentifier || x; }).length + ' service(s)');
      return dev(n, reasons.length ? reasons : ['Delegation configured'], { Type: n.typeLabel });
    });
  };

  // ---- ACL -----------------------------------------------------------------

  var DCSYNC_RIGHTS = { 'DCSync': 1, 'GetChangesAll': 1 };

  CHECKS['dcsync-rights'] = function (ctx) {
    var out = [];
    // Group grantees so each principal is reported once with the domain it targets.
    var byPrincipal = new Map();
    ctx.byType.domains.forEach(function (d) {
      (d.aces || []).forEach(function (a) {
        if (DCSYNC_RIGHTS[a.RightName] && !isDefaultPrincipal(ctx, a.PrincipalSID)) {
          var e = byPrincipal.get(a.PrincipalSID) || { rights: new Set(), domain: d.name };
          e.rights.add(a.RightName); byPrincipal.set(a.PrincipalSID, e);
        }
      });
    });
    byPrincipal.forEach(function (e, sid) {
      var node = ctx.bySid.get(sid) || { sid: sid, name: nameOf(ctx, sid), typeLabel: 'Principal', dn: '', type: 'unknown', props: {} };
      out.push(dev(node, ['Holds ' + Array.from(e.rights).join(' + ') + ' on domain ' + e.domain], {
        Rights: Array.from(e.rights).join(', ')
      }));
    });
    return out;
  };

  var DANGEROUS_RIGHTS = { 'GenericAll': 1, 'WriteDacl': 1, 'WriteOwner': 1, 'Owns': 1, 'GenericWrite': 1, 'AllExtendedRights': 1, 'AddMember': 1, 'WriteAccountRestrictions': 1 };

  CHECKS['dangerous-acl-sensitive'] = function (ctx) {
    var dcs = dcSids(ctx);
    // Build the set of sensitive target SIDs.
    var targets = new Map(); // sid -> node
    ctx.byType.domains.forEach(function (d) { if (d.sid) targets.set(d.sid, d); });
    ctx.privilegedGroupSids.forEach(function (sid) { var n = ctx.bySid.get(sid); if (n) targets.set(sid, n); });
    dcs.forEach(function (sid) { var n = ctx.bySid.get(sid); if (n) targets.set(sid, n); });
    if (ctx.domainSid) { var k = ctx.bySid.get(ctx.domainSid + '-502'); if (k) targets.set(k.sid, k); } // krbtgt
    ctx.all.forEach(function (n) { if (/CN=ADMINSDHOLDER/i.test(n.dn || '')) targets.set(n.sid || n.dn, n); });

    var out = [];
    targets.forEach(function (node) {
      var reasons = [];
      (node.aces || []).forEach(function (a) {
        if (DANGEROUS_RIGHTS[a.RightName] && !isDefaultPrincipal(ctx, a.PrincipalSID)) {
          reasons.push(a.RightName + ' granted to ' + nameOf(ctx, a.PrincipalSID) + (a.IsInherited ? ' (inherited)' : ''));
        }
      });
      if (reasons.length) out.push(dev(node, reasons, { Object: node.typeLabel }));
    });
    return out;
  };

  // ---- Persistence ---------------------------------------------------------

  CHECKS['sid-history-privileged'] = function (ctx) {
    var out = [];
    ctx.all.forEach(function (n) {
      var sh = sidHistoryOf(n);
      if (!sh.length) return;
      var flagged = sh.filter(function (s) {
        var r = rid(s);
        var priv = ctx.privilegedSids.has(s) || [512, 519, 518, 544, 516, 500, 502].indexOf(r) >= 0;
        var foreign = ctx.domainSid && s.indexOf(ctx.domainSid) !== 0 && /^S-1-5-21/.test(s);
        return priv || foreign;
      });
      if (flagged.length) {
        out.push(dev(n, flagged.map(function (s) { return 'sIDHistory contains ' + nameOf(ctx, s) + ' (' + s + ')'; }), {
          Entries: sh.length
        }));
      }
    });
    return out;
  };

  // ---- Hardening / hygiene -------------------------------------------------

  var OBSOLETE_OS = /(windows\s?(2000|xp|vista|7\b|8\b|8\.1)|windows server\s?(2000|2003|2008|2012))/i;

  CHECKS['obsolete-os'] = function (ctx) {
    return ctx.byType.computers.filter(function (n) {
      var os = n.props.operatingsystem || '';
      return enabled(n.props) && OBSOLETE_OS.test(os);
    }).map(function (n) { return dev(n, ['Operating system is no longer supported: ' + n.props.operatingsystem], { OS: n.props.operatingsystem, 'Last logon': fmtTs(n.props.lastlogontimestamp || n.props.lastlogon) }); });
  };

  CHECKS['protected-users-missing'] = function (ctx) {
    if (!ctx.protectedUsersSid) return [];
    return ctx.byType.users.filter(function (n) {
      if (!enabled(n.props)) return false;
      if (!ctx.privilegedSids.has(n.sid)) return false;
      if (rid(n.sid) === 502) return false;
      if (isKerberoastable(n)) return false; // service accounts can't be in Protected Users
      var mo = ctx.memberOf.get(n.sid);
      return !(mo && mo.has(ctx.protectedUsersSid));
    }).map(function (n) { return dev(n, ['Privileged account is not a member of the Protected Users group'], { adminCount: !!n.props.admincount }); });
  };

  CHECKS['admincount-orphan'] = function (ctx) {
    return ctx.byType.users.filter(function (n) {
      return n.props.admincount === true && !ctx.privilegedSids.has(n.sid) && [500, 502].indexOf(rid(n.sid)) < 0;
    }).map(function (n) { return dev(n, ['adminCount=1 but not a member of any privileged group (stale AdminSDHolder ACL)'], { Enabled: enabled(n.props) }); });
  };

  CHECKS['password-never-expires'] = function (ctx) {
    return ctx.byType.users.filter(function (n) {
      return enabled(n.props) && n.props.pwdneverexpires === true && rid(n.sid) !== 502;
    }).map(function (n) {
      return dev(n, ['Password is set to never expire (DONT_EXPIRE_PASSWORD)'], {
        Privileged: ctx.privilegedSids.has(n.sid) ? 'yes' : 'no', 'Password last set': fmtTs(n.props.pwdlastset)
      });
    });
  };

  CHECKS['old-password'] = function (ctx) {
    var now = ctx.referenceNow;
    return ctx.byType.users.filter(function (n) {
      if (!enabled(n.props) || rid(n.sid) === 502) return false;
      var d = days(now, n.props.pwdlastset);
      return d != null && d > OLD_PWD_DAYS;
    }).map(function (n) {
      return dev(n, ['Password last changed ' + days(now, n.props.pwdlastset) + ' days ago (> ' + OLD_PWD_DAYS + ')'], {
        'Password last set': fmtTs(n.props.pwdlastset), adminCount: !!n.props.admincount
      });
    });
  };

  CHECKS['dormant-account'] = function (ctx) {
    var now = ctx.referenceNow;
    return ctx.byType.users.filter(function (n) {
      if (!enabled(n.props) || rid(n.sid) === 502) return false;
      var last = n.props.lastlogontimestamp || n.props.lastlogon || n.props.whencreated;
      var d = days(now, last);
      return d != null && d > DORMANT_DAYS;
    }).map(function (n) {
      var last = n.props.lastlogontimestamp || n.props.lastlogon || n.props.whencreated;
      return dev(n, ['No logon for ' + days(now, last) + ' days (> ' + DORMANT_DAYS + ') but still enabled'], {
        'Last logon': fmtTs(n.props.lastlogontimestamp || n.props.lastlogon)
      });
    });
  };

  CHECKS['laps-missing'] = function (ctx) {
    // Only meaningful if the collector recorded LAPS state for at least one host.
    var known = ctx.byType.computers.some(function (n) { return n.props.haslaps !== undefined; });
    if (!known) return [];
    return ctx.byType.computers.filter(function (n) {
      return enabled(n.props) && n.props.haslaps === false;
    }).map(function (n) { return dev(n, ['Enabled computer has no LAPS-managed local administrator password'], { OS: n.props.operatingsystem || '' }); });
  };

  CHECKS['too-many-admins'] = function (ctx) {
    var thresholds = { '-512': 5, '-519': 2, '-518': 1, '-548': 3 };
    var out = [];
    ctx.privilegedGroupSids.forEach(function (gsid) {
      var node = ctx.bySid.get(gsid); if (!node) return;
      var members = window.BH.effectiveMembers(ctx, gsid);
      var human = 0; members.forEach(function (m) { if (m.type === 'users' || m.type === 'computers') human++; });
      var thr = 5;
      Object.keys(thresholds).forEach(function (suf) { if (gsid.slice(-suf.length) === suf) thr = thresholds[suf]; });
      if (window.BH.isBuiltinAdministrators(gsid)) thr = 10;
      if (human > thr) {
        out.push(dev(node, ['Group has ' + human + ' effective member accounts (recommended ≤ ' + thr + ')'], {
          'Effective members': members.size, 'Recommended max': thr
        }));
      }
    });
    return out;
  };

  CHECKS['disabled-in-priv-group'] = function (ctx) {
    var out = [], seen = new Set();
    ctx.privilegedGroupSids.forEach(function (gsid) {
      var members = window.BH.effectiveMembers(ctx, gsid);
      members.forEach(function (n, sid) {
        if (seen.has(sid)) return;
        if ((n.type === 'users' || n.type === 'computers') && n.props.enabled === false) {
          seen.add(sid);
          out.push(dev(n, ['Disabled account is still a member of a privileged group'], { Type: n.typeLabel }));
        }
      });
    });
    return out;
  };

  CHECKS['machine-account-quota'] = function (ctx) {
    var out = [];
    ctx.byType.domains.forEach(function (d) {
      var q = d.props['ms-ds-machineaccountquota'];
      if (q === undefined) q = d.props.machineaccountquota;
      if (q === undefined) return;
      var n = Number(q);
      if (isFinite(n) && n > 0) out.push(dev(d, ['Any user can create up to ' + n + ' computer account(s) (ms-DS-MachineAccountQuota)'], { Quota: n }));
    });
    return out;
  };

  CHECKS['domain-functional-level'] = function (ctx) {
    return ctx.byType.domains.filter(function (d) {
      var fl = String(d.props.functionallevel || '');
      return /(2000|2003|2008|2012)/.test(fl);
    }).map(function (d) { return dev(d, ['Domain functional level is outdated: ' + d.props.functionallevel], { 'Functional level': d.props.functionallevel }); });
  };

  CHECKS['guest-enabled'] = function (ctx) {
    return ctx.byType.users.filter(function (n) { return rid(n.sid) === 501 && enabled(n.props); })
      .map(function (n) { return dev(n, ['Built-in Guest account (RID 501) is enabled'], {}); });
  };

  // ---- ADCS (Certified Pre-Owned ESC techniques) ---------------------------

  CHECKS['adcs-esc1'] = function (ctx) {
    var out = [];
    (ctx.byType.certtemplates || []).forEach(function (t) {
      var p = t.props;
      if (p.enabled === false) return;
      if (!suppliesSubject(p) || !hasAuthEku(p)) return;
      if (requiresApproval(p) || authorizedSignatures(p) > 0) return;
      var enrollers = lowPrivEnrollers(ctx, t);
      if (!enrollers.length) return;
      out.push(dev(t, ['Enrollee supplies subject + authentication EKU + no manager approval']
        .concat(enrollers.map(function (s) { return 'Enrollable by ' + nameOf(ctx, s); })), {
        EKUs: ekusOf(p).join(', ') || '(any)', 'Manager approval': requiresApproval(p)
      }));
    });
    return out;
  };

  CHECKS['adcs-esc2-esc3'] = function (ctx) {
    var out = [];
    (ctx.byType.certtemplates || []).forEach(function (t) {
      var p = t.props;
      if (p.enabled === false || requiresApproval(p)) return;
      var anyp = isAnyPurpose(p), ea = isEnrollmentAgent(p);
      if (!anyp && !ea) return;
      var enrollers = lowPrivEnrollers(ctx, t);
      if (!enrollers.length) return;
      var reasons = [];
      if (anyp) reasons.push('Template offers Any Purpose / SubCA EKU (ESC2)');
      if (ea) reasons.push('Template offers Certificate Request Agent EKU (ESC3)');
      reasons = reasons.concat(enrollers.map(function (s) { return 'Enrollable by ' + nameOf(ctx, s); }));
      out.push(dev(t, reasons, { EKUs: ekusOf(p).join(', ') || '(any)' }));
    });
    return out;
  };

  var TEMPLATE_WRITE = { 'GenericAll': 1, 'GenericWrite': 1, 'WriteDacl': 1, 'WriteOwner': 1, 'Owns': 1, 'WritePKIEnrollmentFlag': 1, 'WritePKINameFlag': 1 };

  CHECKS['adcs-esc4'] = function (ctx) {
    var out = [];
    (ctx.byType.certtemplates || []).forEach(function (t) {
      var reasons = [];
      (t.aces || []).forEach(function (a) {
        if (TEMPLATE_WRITE[a.RightName] && !isDefaultPrincipal(ctx, a.PrincipalSID)) {
          reasons.push(a.RightName + ' granted to ' + nameOf(ctx, a.PrincipalSID) + (a.IsInherited ? ' (inherited)' : ''));
        }
      });
      if (reasons.length) out.push(dev(t, reasons, { Template: t.name }));
    });
    return out;
  };

  CHECKS['adcs-esc6'] = function (ctx) {
    var out = [];
    enterpriseCAs(ctx).forEach(function (c) {
      var p = c.props;
      if (p.isuserspecifiessanenabled === true || p.userspecifiedsan === true || p.editflags_attributesubjectaltname2 === true) {
        out.push(dev(c, ['CA honours requester-supplied Subject Alternative Name (EDITF_ATTRIBUTESUBJECTALTNAME2)'], { CA: c.name }));
      }
    });
    return out;
  };

  var CA_MGMT = { 'ManageCA': 1, 'ManageCertificates': 1 };

  CHECKS['adcs-esc7'] = function (ctx) {
    var out = [];
    enterpriseCAs(ctx).forEach(function (c) {
      var reasons = [];
      (c.aces || []).forEach(function (a) {
        if (CA_MGMT[a.RightName] && !isDefaultPrincipal(ctx, a.PrincipalSID)) reasons.push(a.RightName + ' granted to ' + nameOf(ctx, a.PrincipalSID));
      });
      if (reasons.length) out.push(dev(c, reasons, { CA: c.name }));
    });
    return out;
  };

  CHECKS['adcs-esc9'] = function (ctx) {
    var out = [];
    (ctx.byType.certtemplates || []).forEach(function (t) {
      var p = t.props;
      if (p.enabled === false) return;
      if (p.nosecurityextension !== true || !hasAuthEku(p)) return;
      var enrollers = lowPrivEnrollers(ctx, t);
      var reasons = ['Template sets CT_FLAG_NO_SECURITY_EXTENSION (ESC9)'];
      if (enrollers.length) reasons.push('Enrollable by ' + enrollers.map(function (s) { return nameOf(ctx, s); }).join(', '));
      out.push(dev(t, reasons, { EKUs: ekusOf(p).join(', ') || '(any)' }));
    });
    return out;
  };

  // ---- Group Policy --------------------------------------------------------

  var GPO_WRITE = { 'GenericAll': 1, 'GenericWrite': 1, 'WriteDacl': 1, 'WriteOwner': 1, 'Owns': 1, 'WriteGPLink': 1 };

  CHECKS['gpo-dangerous-acl'] = function (ctx) {
    var out = [];
    (ctx.byType.gpos || []).forEach(function (g) {
      var reasons = [];
      (g.aces || []).forEach(function (a) {
        if (GPO_WRITE[a.RightName] && !isDefaultPrincipal(ctx, a.PrincipalSID)) {
          reasons.push(a.RightName + ' granted to ' + nameOf(ctx, a.PrincipalSID) + (a.IsInherited ? ' (inherited)' : ''));
        }
      });
      if (reasons.length) out.push(dev(g, reasons, { GPO: g.name }));
    });
    return out;
  };

  CHECKS['gpo-unlinked-disabled'] = function (ctx) {
    // Collect every GPO that something links to. Only meaningful if link data exists.
    var linked = new Set();
    ['domains', 'ous', 'containers'].forEach(function (tp) {
      (ctx.byType[tp] || []).forEach(function (o) {
        var links = (o.raw && o.raw.Links) || [];
        links.forEach(function (l) {
          var g = l.GUID || l.ObjectIdentifier || l.GPOIdentifier;
          if (g) linked.add(String(g).toUpperCase());
        });
      });
    });
    if (linked.size === 0) return []; // collector did not gather link info
    var out = [];
    (ctx.byType.gpos || []).forEach(function (g) {
      var id = String(g.sid || '').toUpperCase();
      if (id && !linked.has(id)) out.push(dev(g, ['GPO is not linked to any site, domain, or OU'], { GPO: g.name }));
    });
    return out;
  };

  // ---- Trust relationships -------------------------------------------------

  // Trusts are not graph nodes, so build a pseudo-node for the deviant table.
  function trustNode(t) {
    return {
      sid: t.targetSid || (t.sourceSid + ' -> ' + t.targetName),
      name: t.sourceName + ' → ' + t.targetName,
      typeLabel: 'Trust', dn: '', type: 'trust', props: {}
    };
  }
  function trustAttrs(t) {
    return {
      Type: t.type, Direction: t.direction, Transitive: t.transitive,
      'SID filtering': t.sidFiltering === undefined ? 'not collected' : (t.sidFiltering ? 'enabled' : 'disabled'),
      'TGT delegation': t.tgtDelegation === undefined ? 'not collected' : (t.tgtDelegation ? 'enabled' : 'disabled')
    };
  }
  // Inside a forest the boundary is the forest, so SID filtering is not applied
  // to ParentChild / CrossLink trusts - flagging those would be a false positive.
  function isCrossBoundary(t) {
    return t.type === 'External' || t.type === 'Forest' || t.type === 'Unknown';
  }

  CHECKS['trust-sid-filtering-disabled'] = function (ctx) {
    return (ctx.trusts || []).filter(function (t) {
      return isCrossBoundary(t) && t.sidFiltering === false && t.direction !== 'Disabled';
    }).map(function (t) {
      return dev(trustNode(t), [
        'SID filtering is disabled on this ' + t.type + ' trust',
        'Principals in ' + t.targetName + ' can inject privileged SIDs into ' + t.sourceName
      ], trustAttrs(t));
    });
  };

  CHECKS['trust-tgt-delegation'] = function (ctx) {
    return (ctx.trusts || []).filter(function (t) {
      return isCrossBoundary(t) && t.tgtDelegation === true && t.direction !== 'Disabled';
    }).map(function (t) {
      return dev(trustNode(t), [
        'TGT delegation is enabled across this ' + t.type + ' trust',
        'Unconstrained delegation hosts in ' + t.targetName + ' can capture TGTs from ' + t.sourceName
      ], trustAttrs(t));
    });
  };

  CHECKS['trust-transitive-external'] = function (ctx) {
    return (ctx.trusts || []).filter(function (t) {
      return t.type === 'External' && t.transitive === true && t.direction !== 'Disabled';
    }).map(function (t) {
      var reasons = ['External trust is transitive (external trusts should be non-transitive)'];
      if (t.direction === 'Bidirectional') reasons.push('Trust is also bidirectional, so access flows both ways');
      return dev(trustNode(t), reasons, trustAttrs(t));
    });
  };

  CHECKS['trust-uncollected-domain'] = function (ctx) {
    var sids = new Set(), names = new Set();
    (ctx.byType.domains || []).forEach(function (d) {
      if (d.sid) sids.add(d.sid);
      names.add(String(d.props.name || d.name || '').toUpperCase());
    });
    return (ctx.trusts || []).filter(function (t) {
      if (t.direction === 'Disabled') return false;
      if (t.targetSid && sids.has(t.targetSid)) return false;
      return !names.has(t.targetName);
    }).map(function (t) {
      return dev(trustNode(t), [
        t.targetName + ' is trusted but was not collected - attack paths across this trust are not visible'
      ], trustAttrs(t));
    });
  };

  // ---- Hygiene and lifecycle ----------------------------------------------
  // Mirrors the "Hygiene and Lifecycle" detection family of Identity Exposure:
  // the same checks as above, but split out when the object is tier-0.

  var DC_DORMANT_DAYS = 45; // DCs authenticate constantly, so the bar is lower

  function isPrivilegedComputer(ctx, node, dcs) {
    return dcs.has(node.sid) || ctx.privilegedSids.has(node.sid);
  }
  function lastLogonOf(p) { return p.lastlogontimestamp || p.lastlogon || null; }

  CHECKS['obsolete-os-privileged'] = function (ctx) {
    var now = ctx.referenceNow, dcs = dcSids(ctx);
    return ctx.byType.computers.filter(function (n) {
      var os = n.props.operatingsystem || '';
      return OBSOLETE_OS.test(os) && isPrivilegedComputer(ctx, n, dcs);
    }).map(function (n) {
      var d = days(now, lastLogonOf(n.props));
      var active = d != null && d <= DORMANT_DAYS;
      return dev(n, [
        'Tier-0 computer runs an unsupported operating system: ' + n.props.operatingsystem,
        active ? 'Machine is still active (last logon ' + d + ' days ago)'
               : 'Machine appears inactive' + (d != null ? ' (last logon ' + d + ' days ago)' : ''),
        dcs.has(n.sid) ? 'Object is a Domain Controller' : 'Object is a member of a privileged group'
      ], { OS: n.props.operatingsystem, 'Last logon': fmtTs(lastLogonOf(n.props)), Enabled: enabled(n.props) });
    });
  };

  CHECKS['dormant-privileged-account'] = function (ctx) {
    var now = ctx.referenceNow;
    return ctx.byType.users.filter(function (n) {
      if (!enabled(n.props) || rid(n.sid) === 502) return false;
      if (!ctx.privilegedSids.has(n.sid)) return false;
      var last = lastLogonOf(n.props);
      if (!ts(last)) return true; // never logged on
      return days(now, last) > DORMANT_DAYS;
    }).map(function (n) {
      var last = lastLogonOf(n.props);
      var never = !ts(last);
      return dev(n, [
        never ? 'Privileged account has never been used'
              : 'Privileged account has not logged on for ' + days(now, last) + ' days',
        'Account is still enabled and holds privileged group membership'
      ], {
        'Last logon': fmtTs(last), 'Password last set': fmtTs(n.props.pwdlastset),
        adminCount: !!n.props.admincount
      });
    });
  };

  CHECKS['dormant-domain-controller'] = function (ctx) {
    var now = ctx.referenceNow, dcs = dcSids(ctx), out = [];
    dcs.forEach(function (sid) {
      var n = ctx.bySid.get(sid);
      if (!n || n.type !== 'computers') return;
      var last = lastLogonOf(n.props);
      var d = days(now, last);
      if (d == null || d <= DC_DORMANT_DAYS) return;
      out.push(dev(n, [
        'Domain Controller has not authenticated for ' + d + ' days (> ' + DC_DORMANT_DAYS + ')',
        'Usually a decommissioned DC whose object was never cleaned up'
      ], { 'Last logon': fmtTs(last), OS: n.props.operatingsystem || '', Enabled: enabled(n.props) }));
    });
    return out;
  };

  // Empty / single-member groups, split privileged vs not, like it does.
  function groupSizeFindings(ctx, wantPrivileged) {
    var out = [];
    (ctx.byType.groups || []).forEach(function (g) {
      if (!g.sid) return;
      // Domain Users / Domain Computers are computed groups: membership is implicit
      if (/-(513|515|514)$/.test(g.sid)) return;
      var isPriv = ctx.privilegedGroupSids.has(g.sid) || g.props.admincount === true;
      if (isPriv !== wantPrivileged) return;
      // Built-in groups (BUILTIN\* and RID < 1000) are created by AD and are commonly
      // empty by design, so they are only noise in the non-privileged hygiene check.
      if (!wantPrivileged) {
        var r = rid(g.sid);
        if (g.sid.indexOf('S-1-5-32-') === 0 || (r != null && r < 1000)) return;
      }
      var members = window.BH.effectiveMembers(ctx, g.sid);
      if (members.size > 1) return;
      out.push(dev(g, [
        members.size === 0 ? 'Group is empty' : 'Group has a single member',
        wantPrivileged ? 'Group is privileged, so the unused rights remain in place'
                       : 'Unused group adds directory clutter and slows access reviews'
      ], {
        Members: members.size,
        Member: members.size === 1 ? Array.from(members.values())[0].name : ''
      }));
    });
    return out;
  }

  CHECKS['priv-group-size'] = function (ctx) { return groupSizeFindings(ctx, true); };
  CHECKS['group-size-hygiene'] = function (ctx) { return groupSizeFindings(ctx, false); };

  CHECKS['duplicate-objects'] = function (ctx) {
    var out = [], bySam = new Map();
    ['users', 'computers', 'groups'].forEach(function (t) {
      (ctx.byType[t] || []).forEach(function (n) {
        var sam = String(n.props.samaccountname || '').toLowerCase();
        if (sam) {
          var arr = bySam.get(sam) || [];
          arr.push(n); bySam.set(sam, arr);
        }
        // replication conflicts are marked with CNF: in the DN
        if (/CNF:/i.test(n.dn || '') || /CNF:/i.test(n.name || '')) {
          out.push(dev(n, ['Object is in a replication-conflict state (CNF: marker in its name)'],
            { Type: n.typeLabel }));
        }
      });
    });
    bySam.forEach(function (arr, sam) {
      if (arr.length < 2) return;
      out.push(dev(arr[0], [
        'sAMAccountName "' + sam + '" is used by ' + arr.length + ' objects',
        'Shared by: ' + arr.map(function (x) { return x.name; }).join(', ')
      ], { Duplicates: arr.length }));
    });
    return out;
  };

  // ---- Entra ID (AzureHound data) -----------------------------------------
  // These only run when an AzureHound export was loaded; bloodhound-python does
  // not collect Entra ID, so without that file they stay silent instead of
  // reporting a clean result they cannot prove.

  var AZ_DORMANT_DAYS = 90;

  function azReady(ctx) { return ctx.az && ctx.az.present; }
  function azNode(o, label) {
    return { sid: o.id, name: o.name, typeLabel: label, dn: o.upn || '', type: 'entra', props: {} };
  }
  // Split "dormant" from "never signed in", and skip the never-case entirely when
  // the export carries no sign-in data at all (otherwise everything looks unused).
  function azStaleState(ctx, o, now) {
    if (o.lastSignIn) {
      var d = Math.floor((now - o.lastSignIn) / DAY);
      return d > AZ_DORMANT_DAYS ? { stale: true, never: false, days: d } : { stale: false };
    }
    if (!ctx.az.hasSignInData) return { stale: false }; // field not collected
    return { stale: true, never: true, days: null };
  }

  function azStaleUsers(ctx, wantPrivileged) {
    if (!azReady(ctx)) return [];
    var now = ctx.referenceNow, out = [];
    ctx.az.users.forEach(function (u) {
      if (!u.enabled) return;
      var isPriv = ctx.az.privileged.has(u.id);
      if (isPriv !== wantPrivileged) return;
      var st = azStaleState(ctx, u, now);
      if (!st.stale) return;
      var reasons = [st.never
        ? (wantPrivileged ? 'Privileged Entra ID account has never signed in' : 'Entra ID account has never signed in')
        : (wantPrivileged ? 'Privileged Entra ID account has not signed in for ' + st.days + ' days'
                          : 'Entra ID account has not signed in for ' + st.days + ' days')];
      if (wantPrivileged) reasons.push('Directory role: ' + ctx.az.privileged.get(u.id));
      out.push(dev(azNode(u, 'AZUser'), reasons, {
        UPN: u.upn, 'Last sign-in': u.lastSignIn ? fmtTs(u.lastSignIn) : 'never',
        Created: u.created ? fmtTs(u.created) : '',
        'Hybrid (synced from AD)': u.onPremSid ? 'yes' : 'no'
      }));
    });
    return out;
  }

  CHECKS['az-dormant-privileged-user'] = function (ctx) { return azStaleUsers(ctx, true); };
  CHECKS['az-dormant-user'] = function (ctx) { return azStaleUsers(ctx, false); };

  CHECKS['az-dormant-device'] = function (ctx) {
    if (!azReady(ctx)) return [];
    var now = ctx.referenceNow, out = [];
    ctx.az.devices.forEach(function (d0) {
      if (!d0.enabled) return;
      var st = azStaleState(ctx, d0, now);
      if (!st.stale) return;
      out.push(dev(azNode(d0, 'AZDevice'), [
        st.never ? 'Registered device has never signed in since it was created'
                 : 'Registered device has not signed in for ' + st.days + ' days'
      ], {
        OS: d0.os, 'Trust type': d0.trustType,
        'Last sign-in': d0.lastSignIn ? fmtTs(d0.lastSignIn) : 'never',
        Created: d0.created ? fmtTs(d0.created) : ''
      }));
    });
    return out;
  };

  CHECKS['az-group-hygiene'] = function (ctx) {
    if (!azReady(ctx)) return [];
    // Without any membership data every group would look empty.
    if (ctx.az.members.size === 0) return [];
    var out = [];
    ctx.az.groups.forEach(function (g) {
      var members = ctx.az.members.get(g.id);
      var n = members ? members.size : 0;
      if (n > 1) return;
      var reasons = [n === 0 ? 'Entra ID group is empty' : 'Entra ID group has a single member'];
      if (g.roleAssignable) reasons.push('Group is role-assignable, so it can carry a directory role');
      out.push(dev(azNode(g, 'AZGroup'), reasons, {
        Members: n, 'Role assignable': g.roleAssignable ? 'yes' : 'no',
        'Security enabled': g.securityEnabled ? 'yes' : 'no'
      }));
    });
    return out;
  };

  // ---- deviant helper ------------------------------------------------------

  function dev(node, reasons, attrs) {
    return {
      sid: node.sid || node.dn || node.name,
      name: node.name,
      type: node.typeLabel || node.type || '',
      dn: node.dn || '',
      reasons: reasons || [],
      attrs: attrs || {}
    };
  }

  // Run every check, returning { id: deviants[] }.
  function runAll(ctx) {
    var results = {};
    window.IOE_CATALOG.forEach(function (c) {
      var fn = CHECKS[c.id];
      try {
        results[c.id] = fn ? (fn(ctx) || []) : [];
      } catch (e) {
        results[c.id] = [];
        ctx.warnings.push('Check "' + c.id + '" failed: ' + e.message);
      }
    });
    return results;
  }

  // Indicators that can only be judged when the matching data source was loaded.
  // Without it they must read as "not assessed", never as "clean".
  var APPLIES = {
    'az-dormant-privileged-user': azReady,
    'az-dormant-user': azReady,
    'az-dormant-device': azReady,
    'az-group-hygiene': azReady
  };

  window.IOE_CHECKS = { runAll: runAll, CHECKS: CHECKS, APPLIES: APPLIES };
})();
