/*
 * UI + orchestration for the BloodHound Indicators of Exposure viewer.
 * Classic script (no ES modules) so the page also works from file://.
 */
(function () {
  'use strict';

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var el = function (tag, cls, html) { var e = document.createElement(tag); if (cls) e.className = cls; if (html != null) e.innerHTML = html; return e; };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); };

  var SEV = [
    { key: 'crit', label: 'Critical', min: 76 },
    { key: 'high', label: 'High', min: 51 },
    { key: 'med', label: 'Medium', min: 26 },
    { key: 'low', label: 'Low', min: 0 }
  ];
  function sevOf(crit) { for (var i = 0; i < SEV.length; i++) if (crit >= SEV[i].min) return SEV[i]; return SEV[SEV.length - 1]; }
  function sevWeight(k) { return { crit: 6, high: 3, med: 1.2, low: 0.4 }[k] || 1; }

  var STATE = { ctx: null, results: null, showAll: false, search: '', findings: null };

  // ------------------------------------------------------------------ loading
  function readFileText(file) {
    return new Promise(function (res, rej) {
      var r = new FileReader();
      r.onload = function () { res(r.result); };
      r.onerror = function () { rej(r.error); };
      r.readAsText(file);
    });
  }
  function readFileBuffer(file) {
    return new Promise(function (res, rej) {
      var r = new FileReader();
      r.onload = function () { res(r.result); };
      r.onerror = function () { rej(r.error); };
      r.readAsArrayBuffer(file);
    });
  }

  // Minimal ZIP reader (BloodHound CE ships a .zip of the JSON files).
  function inflateRaw(bytes) {
    if (typeof DecompressionStream === 'undefined') return Promise.reject(new Error('DecompressionStream unavailable'));
    var ds = new DecompressionStream('deflate-raw');
    var stream = new Response(bytes).body.pipeThrough(ds);
    return new Response(stream).arrayBuffer().then(function (ab) { return new Uint8Array(ab); });
  }
  function readZip(buffer) {
    var dv = new DataView(buffer), u8 = new Uint8Array(buffer), td = new TextDecoder();
    // find End Of Central Directory record.
    var eocd = -1;
    for (var i = dv.byteLength - 22; i >= 0; i--) { if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; } }
    if (eocd < 0) return Promise.reject(new Error('Not a zip'));
    var count = dv.getUint16(eocd + 10, true);
    var cdOff = dv.getUint32(eocd + 16, true);
    var p = cdOff, entries = [];
    for (var n = 0; n < count; n++) {
      if (dv.getUint32(p, true) !== 0x02014b50) break;
      var method = dv.getUint16(p + 10, true);
      var compSize = dv.getUint32(p + 20, true);
      var nameLen = dv.getUint16(p + 28, true);
      var extraLen = dv.getUint16(p + 30, true);
      var commentLen = dv.getUint16(p + 32, true);
      var localOff = dv.getUint32(p + 42, true);
      var name = td.decode(u8.subarray(p + 46, p + 46 + nameLen));
      entries.push({ name: name, method: method, compSize: compSize, localOff: localOff });
      p += 46 + nameLen + extraLen + commentLen;
    }
    var out = [];
    return entries.reduce(function (chain, e) {
      return chain.then(function () {
        if (!/\.json$/i.test(e.name)) return;
        var lh = e.localOff;
        if (dv.getUint32(lh, true) !== 0x04034b50) return;
        var nLen = dv.getUint16(lh + 26, true), xLen = dv.getUint16(lh + 28, true);
        var start = lh + 30 + nLen + xLen;
        var comp = u8.subarray(start, start + e.compSize);
        var pj = e.method === 0 ? Promise.resolve(comp) : inflateRaw(comp);
        return pj.then(function (raw) {
          try { out.push({ name: e.name.split('/').pop(), json: JSON.parse(new TextDecoder().decode(raw)) }); } catch (err) {}
        });
      });
    }, Promise.resolve()).then(function () { return out; });
  }

  // Turn a mixed list of File objects into parsed BloodHound files.
  function ingestFiles(fileList) {
    var files = Array.prototype.slice.call(fileList);
    var jobs = files.map(function (f) {
      if (/\.zip$/i.test(f.name)) return readFileBuffer(f).then(readZip).catch(function () { return []; });
      if (/\.json$/i.test(f.name)) return readFileText(f).then(function (t) {
        try { return [{ name: f.name, json: JSON.parse(t) }]; } catch (e) { return []; }
      });
      return Promise.resolve([]);
    });
    return Promise.all(jobs).then(function (arrs) {
      return arrs.reduce(function (a, b) { return a.concat(b); }, []);
    });
  }

  // Drag/drop that also walks dropped folders.
  function entriesFromDataTransfer(dt) {
    var items = dt.items ? Array.prototype.slice.call(dt.items) : [];
    var roots = items.map(function (it) { return it.webkitGetAsEntry && it.webkitGetAsEntry(); }).filter(Boolean);
    if (!roots.length) return Promise.resolve(Array.prototype.slice.call(dt.files || []));
    var files = [];
    function walk(entry) {
      return new Promise(function (res) {
        if (entry.isFile) { entry.file(function (f) { files.push(f); res(); }, res); }
        else if (entry.isDirectory) {
          var reader = entry.createReader(), all = [];
          (function readMore() {
            reader.readEntries(function (batch) {
              if (!batch.length) { Promise.all(all.map(walk)).then(res); return; }
              all = all.concat(batch); readMore();
            }, res);
          })();
        } else res();
      });
    }
    return Promise.all(roots.map(walk)).then(function () { return files; });
  }

  function load(fileList) {
    ingestFiles(fileList).then(function (files) {
      if (!files.length) { alert('No BloodHound JSON files were found in the selection.'); return; }
      var ctx = window.BH.normalize(files);
      var results = window.IOE_CHECKS.runAll(ctx);
      STATE.ctx = ctx; STATE.results = results;
      STATE.findings = buildFindings(ctx, results);
      render();
    }).catch(function (e) { alert('Failed to read files: ' + e.message); });
  }

  // ------------------------------------------------------------------ compute
  function buildFindings(ctx, results) {
    var applies = (window.IOE_CHECKS && window.IOE_CHECKS.APPLIES) || {};
    return window.IOE_CATALOG.map(function (c) {
      var devs = results[c.id] || [];
      var s = sevOf(c.criticity);
      // "not assessed" is not the same as "clean" - keep them apart
      var na = applies[c.id] ? !applies[c.id](ctx) : false;
      return { cat: c, sev: s, count: devs.length, deviants: devs, na: na };
    });
  }

  // Heuristic 0-100 maturity score. Bounded exponential decay so a very messy
  // domain approaches, but never floors at, 0 and stays comparable over time.
  function exposureScore(findings) {
    var penalty = 0;
    findings.forEach(function (f) {
      if (!f.count) return;
      var base = sevWeight(f.sev.key);
      penalty += Math.min(base * 3, base * (1 + Math.log10(f.count)));
    });
    return 100 * Math.exp(-penalty / 180);
  }

  // ------------------------------------------------------------------ render
  function render() {
    $('#dropzone').classList.add('hidden');
    $('#app').classList.remove('hidden');
    var ctx = STATE.ctx, findings = STATE.findings;

    var assessed = findings.filter(function (f) { return !f.na; });
    var notAssessed = findings.filter(function (f) { return f.na; });
    var active = assessed.filter(function (f) { return f.count > 0; });
    var byKey = { crit: 0, high: 0, med: 0, low: 0 };
    active.forEach(function (f) { byKey[f.sev.key]++; });
    var totalDev = active.reduce(function (a, f) { return a + f.count; }, 0);

    // summary
    var sm = $('#summary'); sm.innerHTML = '';
    sm.appendChild(stat('Domain', esc(ctx.domainName || 'Unknown'), (ctx.byType.users.length) + ' users · ' + (ctx.byType.computers.length) + ' computers'));
    sm.appendChild(stat('Exposure score', exposureScore(findings).toFixed(2), 'heuristic, 0–100', 'score'));
    sm.appendChild(stat('Indicators', String(assessed.length),
      active.length + ' with findings' + (notAssessed.length ? ' · ' + notAssessed.length + ' not assessed' : '')));
    sm.appendChild(stat('Deviant objects', totalDev.toLocaleString(), 'across all indicators'));
    var sev = stat('By severity', '', '');
    sev.querySelector('.v').innerHTML =
      '<span class="sev-dot dot-crit"></span>' + byKey.crit +
      ' <span class="sev-dot dot-high" style="margin-left:8px"></span>' + byKey.high +
      ' <span class="sev-dot dot-med" style="margin-left:8px"></span>' + byKey.med +
      ' <span class="sev-dot dot-low" style="margin-left:8px"></span>' + byKey.low;
    sev.querySelector('.v').style.fontSize = '20px';
    sm.appendChild(sev);

    // warnings, plus anything we could not judge for lack of a data source
    var notes = (ctx.warnings || []).slice();
    if (notAssessed.length) {
      notes.push(notAssessed.length + ' indicator(s) not assessed — no data source loaded for: '
        + notAssessed.map(function (f) { return f.cat.category; })
            .filter(function (v, i, a) { return a.indexOf(v) === i; }).join(', ')
        + '. Entra ID checks need an AzureHound export; bloodhound-python does not collect it.');
    }
    var wb = $('#warnbar');
    if (notes.length) { wb.classList.remove('hidden'); wb.textContent = notes.join('  •  '); }
    else wb.classList.add('hidden');

    renderSections();
  }

  function stat(k, v, sub, extra) {
    var s = el('div', 'stat' + (extra ? ' ' + extra : ''));
    s.appendChild(el('div', 'k', k));
    s.appendChild(el('div', 'v', v));
    if (sub) s.appendChild(el('div', 'sub', sub));
    return s;
  }

  function complexityDots(c) {
    var lvl = Math.max(1, Math.min(5, Math.round(c / 20)));
    var d = '';
    for (var i = 1; i <= 5; i++) d += '<span class="cd' + (i <= lvl ? ' on' : '') + '"></span>';
    return '<span class="complexity" title="Remediation complexity">Complexity <span class="dots">' + d + '</span></span>';
  }

  function renderSections() {
    var host = $('#sections'); host.innerHTML = '';
    var findings = STATE.findings.filter(function (f) { return !f.na; });
    var q = STATE.search.trim().toLowerCase();
    if (q) findings = findings.filter(function (f) {
      return f.cat.name.toLowerCase().indexOf(q) >= 0 || f.cat.description.toLowerCase().indexOf(q) >= 0 || f.cat.category.toLowerCase().indexOf(q) >= 0;
    });

    // sort within severity: most deviants first, then criticity
    SEV.forEach(function (S) {
      var items = findings.filter(function (f) { return f.sev.key === S.key; });
      if (!STATE.showAll) items = items.filter(function (f) { return f.count > 0; });
      items.sort(function (a, b) { return (b.count - a.count) || (b.cat.criticity - a.cat.criticity); });
      if (!items.length) return;

      var head = el('div', 'sev-head');
      head.appendChild(el('span', 'bar bar-' + S.key));
      head.appendChild(document.createTextNode(S.label + ' '));
      var withF = items.filter(function (f) { return f.count > 0; }).length;
      head.appendChild(el('span', 'count', '— ' + withF + ' with findings / ' + items.length + ' indicators'));
      host.appendChild(head);

      var grid = el('div', 'grid');
      items.forEach(function (f) { grid.appendChild(card(f)); });
      host.appendChild(grid);
    });

    if (!host.children.length) host.appendChild(el('div', 'empty', 'No indicators match your search.'));
  }

  function card(f) {
    var clean = f.count === 0;
    var c = el('div', 'card ' + (clean ? 'clean' : f.sev.key));
    c.appendChild(el('div', 'title', esc(f.cat.name)));
    c.appendChild(el('div', 'desc', esc(f.cat.description)));
    var foot = el('div', 'foot');
    var badge = el('span', 'badge ' + (clean ? 'clean' : f.sev.key), clean ? 'No finding' : (f.count.toLocaleString() + (f.count === 1 ? ' object' : ' objects')));
    foot.appendChild(badge);
    foot.insertAdjacentHTML('beforeend', complexityDots(f.cat.complexity));
    c.appendChild(foot);
    c.addEventListener('click', function () { openDetail(f); });
    return c;
  }

  // ------------------------------------------------------------------ detail
  var DETAIL = { finding: null, tab: 'info', devSearch: '', page: 0, perPage: 25 };

  function openDetail(f) {
    DETAIL = { finding: f, tab: 'info', devSearch: '', page: 0, perPage: 25 };
    $('#overlay').classList.add('open');
    var c = f.cat;
    $('#d-title').textContent = c.name;
    $('#d-meta').innerHTML =
      metaItem('Severity', '<span class="sev-dot dot-' + f.sev.key + '"></span>' + f.sev.label + ' (' + c.criticity + ')') +
      metaItem('Category', esc(c.category)) +
      metaItem('Deviant objects', f.count.toLocaleString()) +
      metaItem('Complexity', complexityDots(c.complexity));
    renderTabs();
    renderTabBody();
  }
  function metaItem(k, v) { return '<div class="m"><div class="k">' + k + '</div><div class="val">' + v + '</div></div>'; }

  function renderTabs() {
    var tabs = [['info', 'Information'], ['vuln', 'Vulnerability details'], ['dev', 'Deviant objects'], ['rec', 'Recommendation']];
    if (cypherFor(DETAIL.finding.cat.id)) tabs.push(['cypher', 'BloodHound query']);
    var host = $('#d-tabs'); host.innerHTML = '';
    tabs.forEach(function (t) {
      var b = el('button', 'tab' + (DETAIL.tab === t[0] ? ' active' : ''), t[1] + (t[0] === 'dev' ? ' (' + DETAIL.finding.count + ')' : ''));
      b.addEventListener('click', function () { DETAIL.tab = t[0]; renderTabs(); renderTabBody(); });
      host.appendChild(b);
    });
  }

  function renderTabBody() {
    var host = $('#d-body'); host.innerHTML = '';
    var c = DETAIL.finding.cat;
    if (DETAIL.tab === 'info') {
      var p = el('div', 'prose');
      p.innerHTML = '<p>' + esc(c.description) + '</p>' +
        (c.execSummary ? '<h4>Executive summary</h4><p>' + esc(c.execSummary) + '</p>' : '') +
        (c.tools && c.tools.length ? '<h4>Known attacker tools</h4><div class="chips">' + c.tools.map(function (t) { return '<span class="chip">' + esc(t) + '</span>'; }).join('') + '</div>' : '') +
        (c.references && c.references.length ? '<h4>References</h4><ul>' + c.references.map(function (r) { return '<li><a href="' + esc(r.url) + '" target="_blank" rel="noopener">' + esc(r.name) + '</a></li>'; }).join('') + '</ul>' : '');
      host.appendChild(p);
    } else if (DETAIL.tab === 'vuln') {
      host.appendChild(el('div', 'prose', '<h4>Vulnerability details</h4><p>' + esc(c.vulnDetail).replace(/`([^`]+)`/g, '<code>$1</code>') + '</p>'));
    } else if (DETAIL.tab === 'rec') {
      host.appendChild(el('div', 'prose', '<h4>Recommendation</h4><p>' + esc(c.recommendation) + '</p>'));
    } else if (DETAIL.tab === 'cypher') {
      renderCypher(host, c);
    } else {
      renderDeviants(host);
    }
  }

  function cypherFor(id) { return (window.IOE_CYPHER || {})[id] || null; }

  // The same finding, expressed as a query you can run in BloodHound itself.
  function renderCypher(host, cat) {
    var entry = cypherFor(cat.id);
    if (!entry) { host.appendChild(el('div', 'empty', 'No BloodHound query for this indicator.')); return; }

    var wrap = el('div', 'prose');
    wrap.appendChild(el('p', null,
      'Run this in <strong>BloodHound CE &rarr; Explore &rarr; Cypher</strong> (or Neo4j for Legacy) to get the same finding straight from the graph.'
      + (entry.ioe ? ' Identity Exposure equivalent: <code>' + esc(entry.ioe) + '</code>.' : '')));

    var bar = el('div', 'dev-toolbar');
    var copy = el('button', 'btn primary', 'Copy query');
    copy.addEventListener('click', function () { copyText(entry.query, copy); });
    bar.appendChild(copy);
    wrap.appendChild(bar);

    var pre = el('pre', 'cypher');
    pre.appendChild(el('code', null, esc(entry.query)));
    wrap.appendChild(pre);

    wrap.appendChild(el('p', 'hint-note',
      'Well-known SIDs are matched with <code>ENDS WITH</code> because BloodHound prefixes them with the domain name. '
      + 'If your build rejects <code>datetime()</code>, replace it with a literal epoch.'));
    host.appendChild(wrap);
  }

  function copyText(text, btn) {
    var done = function () {
      var old = btn.textContent;
      btn.textContent = 'Copied';
      setTimeout(function () { btn.textContent = old; }, 1200);
    };
    // clipboard API needs a secure context; fall back for file:// and old browsers
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, function () { legacyCopy(text, done, btn); });
    } else {
      legacyCopy(text, done, btn);
    }
  }
  function legacyCopy(text, done, btn) {
    try {
      var ta = el('textarea');
      ta.value = text;
      ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      var ok = document.execCommand('copy');
      ta.remove();
      if (ok) { done(); return; }
    } catch (e) { /* fall through */ }
    btn.textContent = 'Press Ctrl+C';
    setTimeout(function () { btn.textContent = 'Copy query'; }, 1600);
  }

  function renderDeviants(host) {
    var f = DETAIL.finding;
    var devs = f.deviants.slice();
    var q = DETAIL.devSearch.trim().toLowerCase();
    if (q) devs = devs.filter(function (d) {
      return (d.name || '').toLowerCase().indexOf(q) >= 0 || (d.dn || '').toLowerCase().indexOf(q) >= 0 ||
        d.reasons.join(' ').toLowerCase().indexOf(q) >= 0;
    });

    var tb = el('div', 'dev-toolbar');
    var search = el('input'); search.type = 'search'; search.placeholder = 'Filter ' + devs.length + ' object(s)…'; search.value = DETAIL.devSearch;
    search.addEventListener('input', function () { DETAIL.devSearch = search.value; DETAIL.page = 0; renderDeviants(host); });
    tb.appendChild(search);
    var exp = el('button', 'btn', 'Export CSV');
    exp.addEventListener('click', function () { exportCsv(f); });
    tb.appendChild(exp);
    host.innerHTML = ''; host.appendChild(tb);

    if (!devs.length) { host.appendChild(el('div', 'empty', f.count ? 'No object matches the filter.' : 'No deviant object for this indicator — this check passed.')); return; }

    var pages = Math.ceil(devs.length / DETAIL.perPage);
    if (DETAIL.page >= pages) DETAIL.page = 0;
    var slice = devs.slice(DETAIL.page * DETAIL.perPage, DETAIL.page * DETAIL.perPage + DETAIL.perPage);

    var table = el('table', 'dev');
    table.innerHTML = '<thead><tr><th>Type</th><th>Object</th><th>Reasons</th><th>Attributes</th></tr></thead>';
    var tbody = el('tbody');
    slice.forEach(function (d) {
      var tr = el('tr');
      tr.appendChild(el('td', null, esc(d.type)));
      tr.appendChild(el('td', null, '<div>' + esc(d.name) + '</div>' + (d.dn ? '<div class="mono">' + esc(d.dn) + '</div>' : '<div class="mono">' + esc(d.sid) + '</div>')));
      tr.appendChild(el('td', 'reasons', d.reasons.map(function (r) { return '<span>• ' + esc(r) + '</span>'; }).join('')));
      var attrs = Object.keys(d.attrs || {}).map(function (k) { return '<span>' + esc(k) + ': ' + esc(d.attrs[k]) + '</span>'; }).join('');
      tr.appendChild(el('td', 'reasons', attrs));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    host.appendChild(table);

    if (pages > 1) {
      var pager = el('div', 'pager');
      var prev = el('button', null, 'Prev'); prev.disabled = DETAIL.page === 0;
      prev.addEventListener('click', function () { DETAIL.page--; renderDeviants(host); });
      var next = el('button', null, 'Next'); next.disabled = DETAIL.page >= pages - 1;
      next.addEventListener('click', function () { DETAIL.page++; renderDeviants(host); });
      pager.appendChild(document.createTextNode('Page ' + (DETAIL.page + 1) + ' / ' + pages + ' '));
      pager.appendChild(prev); pager.appendChild(next);
      host.appendChild(pager);
    }
  }

  function toCsv(rows) {
    return rows.map(function (r) {
      return r.map(function (v) { v = v == null ? '' : String(v); return /[",\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; }).join(',');
    }).join('\r\n');
  }
  function download(name, text) {
    var blob = new Blob([text], { type: 'text/csv;charset=utf-8' });
    var a = el('a'); a.href = URL.createObjectURL(blob); a.download = name; document.body.appendChild(a); a.click();
    setTimeout(function () { URL.revokeObjectURL(a.href); a.remove(); }, 0);
  }
  function exportCsv(f) {
    var rows = [['Indicator', 'Severity', 'Type', 'Object', 'DistinguishedName', 'SID', 'Reasons']];
    f.deviants.forEach(function (d) {
      rows.push([f.cat.name, f.sev.label, d.type, d.name, d.dn, d.sid, d.reasons.join(' | ')]);
    });
    download((f.cat.id || 'indicator') + '.csv', toCsv(rows));
  }
  function exportAll() {
    if (!STATE.findings) return;
    var rows = [['Indicator', 'Severity', 'Criticity', 'Category', 'Type', 'Object', 'DistinguishedName', 'SID', 'Reasons']];
    STATE.findings.forEach(function (f) {
      f.deviants.forEach(function (d) {
        rows.push([f.cat.name, f.sev.label, f.cat.criticity, f.cat.category, d.type, d.name, d.dn, d.sid, d.reasons.join(' | ')]);
      });
    });
    download('bloodhound-ioe-findings.csv', toCsv(rows));
  }

  // ------------------------------------------------------------------ wire up
  function init() {
    var dz = $('#dropzone');
    ['dragenter', 'dragover'].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.add('drag'); }); });
    ['dragleave', 'drop'].forEach(function (ev) { dz.addEventListener(ev, function (e) { e.preventDefault(); dz.classList.remove('drag'); }); });
    dz.addEventListener('drop', function (e) { entriesFromDataTransfer(e.dataTransfer).then(load); });
    // allow dropping anywhere once loaded
    document.addEventListener('dragover', function (e) { e.preventDefault(); });
    document.addEventListener('drop', function (e) { if (!$('#app').classList.contains('hidden')) { e.preventDefault(); entriesFromDataTransfer(e.dataTransfer).then(load); } });

    $('#file-input').addEventListener('change', function (e) { load(e.target.files); e.target.value = ''; });
    $('#dir-input').addEventListener('change', function (e) { load(e.target.files); e.target.value = ''; });
    $('#btn-files').addEventListener('click', function () { $('#file-input').click(); });
    $('#btn-dir').addEventListener('click', function () { $('#dir-input').click(); });
    $('#btn-load').addEventListener('click', function () { $('#file-input').click(); });

    $('#search').addEventListener('input', function (e) { STATE.search = e.target.value; renderSections(); });
    $('#showall').addEventListener('change', function (e) { STATE.showAll = e.target.checked; renderSections(); });
    $('#btn-export').addEventListener('click', exportAll);
    $('#btn-theme').addEventListener('click', function () {
      var cur = document.documentElement.getAttribute('data-theme');
      document.documentElement.setAttribute('data-theme', cur === 'dark' ? 'light' : 'dark');
    });

    $('#overlay').addEventListener('click', function (e) { if (e.target.id === 'overlay') $('#overlay').classList.remove('open'); });
    $('#d-close').addEventListener('click', function () { $('#overlay').classList.remove('open'); });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') $('#overlay').classList.remove('open'); });
  }

  // Public hook: load already-fetched files (used for ?demo autoload and testing).
  window.BHIOE = {
    load: load,
    demo: function (dir) {
      dir = dir || 'sample/';
      var names = ['corp_users.json', 'corp_computers.json', 'corp_groups.json', 'corp_domains.json', 'corp_gpos.json', 'corp_ous.json', 'corp_containers.json', 'corp_certtemplates.json', 'corp_enterprisecas.json', 'corp_azure.json'];
      return Promise.all(names.map(function (n) {
        return fetch(dir + n).then(function (r) { return r.ok ? r.text() : null; }).then(function (t) { return t ? new File([t], n, { type: 'application/json' }) : null; }).catch(function () { return null; });
      })).then(function (files) { load(files.filter(Boolean)); });
    }
  };

  document.addEventListener('DOMContentLoaded', function () {
    init();
    if (/[?&]demo/.test(location.search)) window.BHIOE.demo();
  });
})();
