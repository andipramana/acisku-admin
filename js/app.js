// Artosku Admin: a static page that talks to Supabase with the signed-in admin's own session.
// Nothing here decides who may do what: every call below is answered by a database function that
// checks is_admin() (listed email + second factor). A page that is edited in the browser gets the
// same "forbidden" from the server.
(function () {
  'use strict';
  const cfg = window.ADMIN_CONFIG;
  const sb = window.supabase.createClient(cfg.url, cfg.anonKey, {
    auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true, flowType: 'pkce' },
  });

  // ------------------------------------------------------------------ small helpers
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => [...(r || document).querySelectorAll(s)];
  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const num = (n) => Number(n || 0).toLocaleString('id-ID');
  const rp = (n) => 'Rp' + Math.round(Number(n || 0)).toLocaleString('id-ID');
  const usd = (n) => Number(n || 0).toLocaleString('id-ID', { minimumFractionDigits: 3, maximumFractionDigits: 4 });
  const when = (v) => (v ? new Date(v).toLocaleString('id-ID', { timeZone: 'Asia/Jakarta', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) : '—');
  const dayLabel = (d) => String(d).slice(8, 10);
  const mask = (e) => { const s = String(e || ''); const i = s.indexOf('@'); return i < 3 ? s : s.slice(0, 2) + '••••' + s.slice(i); };
  let unmask = false;
  const who = (e) => esc(unmask ? e : mask(e));

  async function rpc(fn, args) {
    const { data, error } = await sb.rpc(fn, args || {});
    if (error) throw error;
    return data;
  }
  function toast(msg, isErr) {
    const t = $('#toast');
    t.textContent = msg; t.className = 'toast' + (isErr ? ' err' : ''); t.style.display = 'block';
    clearTimeout(toast._t); toast._t = setTimeout(() => (t.style.display = 'none'), isErr ? 6000 : 2800);
  }
  const fail = (e) => toast(e && e.message ? e.message : String(e), true);

  function openModal(html) { $('#modalbox').innerHTML = html; $('#modal').classList.add('on'); }
  function closeModal() { $('#modal').classList.remove('on'); }

  // ------------------------------------------------------------------ theme (auto / light / dark)
  const THEMES = ['auto', 'light', 'dark'];
  const THEME_LABEL = { auto: 'Tema: otomatis', light: 'Tema: terang', dark: 'Tema: gelap' };
  function getTheme() { try { return localStorage.getItem('admin-theme') || 'auto'; } catch (e) { return 'auto'; } }
  function applyTheme(t) {
    if (t === 'auto') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
    try { localStorage.setItem('admin-theme', t); } catch (e) { /* private window */ }
    $$('[data-act=theme]').forEach((b) => (b.textContent = THEME_LABEL[t]));
  }

  // ------------------------------------------------------------------ gate: login, admin check, second factor
  const gateBox = () => $('#gatebox');
  function showGate(html) { $('#app').style.display = 'none'; $('#gate').classList.add('on'); gateBox().innerHTML = html; }

  function showLogin(msg) {
    showGate(`<div style="font-size:34px">🐔</div><h2>Artosku Admin</h2>
      <p>Khusus pengelola Artosku. Masuk dengan akun Google yang terdaftar sebagai admin, lalu kode dari aplikasi authenticator.</p>
      <button class="gbtn" data-act="login">Masuk dengan Google</button>
      ${msg ? `<div class="err">${esc(msg)}</div>` : ''}
      <p style="font-size:12px;margin:14px 0 0">Akun lain ditolak oleh server, bukan hanya disembunyikan di halaman ini.</p>
      <button class="themebtn" data-act="theme" style="margin-top:10px"></button>`);
    applyTheme(getTheme());
  }
  async function login() {
    const { error } = await sb.auth.signInWithOAuth({ provider: 'google', options: { redirectTo: location.origin + location.pathname } });
    if (error) fail(error);
  }
  async function signOut() { await sb.auth.signOut(); location.href = location.pathname; }

  function showNotAdmin(email) {
    showGate(`<div style="font-size:34px">🚫</div><h2>Bukan akun admin</h2>
      <p>${esc(email)} tidak terdaftar sebagai admin Artosku.</p>
      <button class="gbtn" data-act="signout">Keluar</button>`);
  }

  async function showMfa() {
    const { data, error } = await sb.auth.mfa.listFactors();
    if (error) return showLogin(error.message);
    const verified = (data.totp || []).find((f) => f.status === 'verified');
    if (verified) {
      showGate(`<h2>Kode verifikasi</h2><p>Masukkan 6 digit dari aplikasi authenticator.</p>
        <input class="code" id="mfacode" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="••••••">
        <button class="btn" style="width:100%;margin-top:12px" data-act="mfa-verify" data-factor="${esc(verified.id)}">Verifikasi</button>
        <div class="err" id="mfaerr"></div><p style="margin-top:14px"><a href="#" data-act="signout">Keluar</a></p>`);
      $('#mfacode').focus();
      return;
    }
    // first time: a clean enrolment (an old, never-finished factor is removed first)
    for (const f of (data.all || []).filter((x) => x.status === 'unverified')) await sb.auth.mfa.unenroll({ factorId: f.id });
    const enr = await sb.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'Artosku Admin ' + Date.now() });
    if (enr.error) return showLogin('Tidak bisa menyiapkan verifikasi dua langkah: ' + enr.error.message);
    const t = enr.data.totp;
    showGate(`<h2>Pasang verifikasi dua langkah</h2>
      <p>Pindai kode ini dengan aplikasi authenticator (Google Authenticator, Authy, 1Password), lalu masukkan 6 digitnya.</p>
      <img class="qr" alt="QR" src="${esc(t.qr_code)}">
      <p class="mono" style="word-break:break-all">${esc(t.secret)}</p>
      <input class="code" id="mfacode" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="••••••">
      <button class="btn" style="width:100%;margin-top:12px" data-act="mfa-verify" data-factor="${esc(enr.data.id)}">Aktifkan</button>
      <div class="err" id="mfaerr"></div><p style="margin-top:14px"><a href="#" data-act="signout">Keluar</a></p>`);
  }
  async function mfaVerify(factorId) {
    const code = ($('#mfacode').value || '').replace(/\D/g, '');
    if (code.length !== 6) { $('#mfaerr').textContent = 'Kode terdiri dari 6 digit.'; return; }
    const { error } = await sb.auth.mfa.challengeAndVerify({ factorId, code });
    if (error) { $('#mfaerr').textContent = 'Kode salah atau kedaluwarsa. Coba lagi.'; return; }
    boot();
  }

  async function boot() {
    try {
      const { data } = await sb.auth.getSession();
      if (history.replaceState && location.search) history.replaceState(null, '', location.pathname + location.hash);
      if (!data.session) return showLogin();
      const status = await rpc('admin_status');
      if (status === 'not_admin') return showNotAdmin(data.session.user.email);
      if (status === 'needs_mfa') return showMfa();
      startApp(data.session);
    } catch (e) { showLogin(e.message || String(e)); }
  }

  // ------------------------------------------------------------------ app shell and routing
  const PAGES = [
    ['ringkasan', '📊', 'Ringkasan', pgRingkasan],
    ['pendaftar', '👥', 'Pendaftar', pgPendaftar],
    ['pengumuman', '📢', 'Pengumuman', pgPengumuman],
    ['pengguna', '👤', 'Pengguna', pgPengguna],
    ['biaya', '💸', 'Biaya AI', pgBiaya],
    ['analisis', '🧠', 'Analisis AI', pgAnalisis],
    ['keuangan', '💰', 'Keuangan', pgKeuangan],
    ['kuota', '⏱️', 'Kuota AI', pgKuota],
    ['rilis', '🚀', 'Rilis & pengaturan', pgRilis],
  ];
  let session = null;
  function startApp(s) {
    session = s;
    $('#gate').classList.remove('on'); $('#app').style.display = '';
    $('#me').textContent = s.user.email; $('#projref').textContent = new URL(cfg.url).hostname.split('.')[0];
    const links = PAGES.map(([k, i, t]) => `<a href="#${k}" data-k="${k}"><span class="i">${i}</span>${t}</a>`).join('');
    $('#nav1').innerHTML = links; $('#nav2').innerHTML = links;
    applyTheme(getTheme());
    route();
  }
  let routeSeq = 0;
  async function route() {
    if (!session) return;
    const k = (location.hash || '#ringkasan').slice(1);
    const page = PAGES.find((p) => p[0] === k) || PAGES[0];
    $$('.nav a').forEach((a) => a.classList.toggle('on', a.dataset.k === page[0]));
    const seq = ++routeSeq;
    $('#main').innerHTML = '<div class="loading">Memuat…</div>';
    try {
      const html = await page[3]();
      if (seq === routeSeq) $('#main').innerHTML = `<section class="page on">${html}</section>`;
    } catch (e) {
      if (seq === routeSeq) $('#main').innerHTML = `<div class="card"><h3>Gagal memuat</h3><p class="hint">${esc(e.message || e)}</p><button class="btn sec" data-act="reload">Coba lagi</button></div>`;
    }
  }
  addEventListener('hashchange', route);

  // ------------------------------------------------------------------ shared pieces
  // A chart: every bar has its number, and tapping a bar shows that day in full underneath.
  const charts = {};
  const longDay = (d) => new Date(d + 'T00:00:00').toLocaleDateString('id-ID', { weekday: 'long', day: 'numeric', month: 'long' });
  function chart(id, items, fmt, detail, opt) {
    opt = opt || {};
    charts[id] = { items, detail };
    const n = items.length, max = Math.max(1, ...items.map((i) => i.v));
    const axisEvery = Math.max(1, Math.ceil(n / 12));
    const showVal = (it, i) => (n <= 16 ? true : it.v === max) && it.v > 0 || (n <= 16 && it.v === 0);
    const axis = items.map((it, i) => `<span>${(n - 1 - i) % axisEvery === 0 ? esc(it.lab) : ''}</span>`).join('');
    const last = opt.sel == null ? n - 1 : opt.sel;
    let body;
    if (opt.type === 'line') {
      const x = (i) => (n === 1 ? 50 : ((i + 0.5) / n) * 100);
      const y = (v) => 100 - (v / max) * 100;
      const pts = items.map((it, i) => `${x(i).toFixed(2)},${y(it.v).toFixed(2)}`).join(' ');
      const dots = items.map((it, i) => `<button type="button" class="bar dot${i === last ? ' sel' : ''}" data-i="${i}" style="left:${x(i)}%;bottom:${(it.v / max) * 100}%" aria-label="${esc(it.aria || it.lab)}: ${esc(fmt(it.v))}"><b>${showVal(it, i) ? esc(fmt(it.v)) : ''}</b></button>`).join('');
      body = `<div class="linebox"><svg class="lsvg" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="var(--barnow)" stroke-width="2.5" vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round"/></svg>${dots}</div>`;
    } else {
      body = `<div class="bars">${items.map((it, i) => `<button type="button" class="bar${i === n - 1 && !opt.noNow ? ' now' : ''}${i === last ? ' sel' : ''}" data-i="${i}" style="height:${Math.max(4, (it.v / max) * 100)}%" aria-label="${esc(it.aria || it.lab)}: ${esc(fmt(it.v))}"><b>${showVal(it, i) ? esc(fmt(it.v)) : ''}</b></button>`).join('')}</div>`;
    }
    return `<div class="chartbox" data-chart="${id}">${body}<div class="axis">${axis}</div><div class="cdetail">${detail(items, last)}</div></div>`;
  }
  function pickBar(bar) {
    const box = bar.closest('.chartbox'), c = charts[box.dataset.chart];
    if (!c) return;
    box.querySelectorAll('.bar').forEach((b) => b.classList.toggle('sel', b === bar));
    box.querySelector('.cdetail').innerHTML = c.detail(c.items, +bar.dataset.i);
  }
  const deltaText = (items, i, unit) => {
    if (i === 0) return '';
    const d = items[i].v - items[i - 1].v;
    return ` · ${d >= 0 ? '+' : '−'}${unit(Math.abs(d))} dari hari sebelumnya`;
  };
  const chip = (cls, t) => `<span class="chip ${cls}">${esc(t)}</span>`;
  const tierChip = (t) => (t === 'max' ? chip('bl', 'Max') : t === 'pro' ? chip('gr', 'Pro') : chip('mu', 'Free'));

  // ------------------------------------------------------------------ Ringkasan
  let sumDays = 14;
  async function pgRingkasan() {
    const [o, su, co, pf, sets] = await Promise.all([rpc('admin_overview'), rpc('admin_signups_per_day', { p_days: sumDays }), rpc('admin_ai_cost_per_day', { p_days: sumDays }), rpc('admin_profit_estimate', { p_days: 30 }), rpc('admin_get_settings')]);
    const y = Number(o.ai_cost_idr_yesterday || 0), t = Number(o.ai_cost_idr_today || 0);
    const delta = y > 0 ? Math.round(((t - y) / y) * 100) : null;
    const rel = o.release || {};
    const rangeChips = [14, 30, 90].map((d) => `<button data-act="sum-days" data-v="${d}" class="${sumDays === d ? 'on' : ''}">${d} hari</button>`).join('');
    const setv = Object.fromEntries((sets || []).map((x) => [x.key, Number(x.value)]));
    const lineN = (plan, kind) => ((pf.lines || []).find((l) => l.plan === plan && l.kind === kind) || { n: 0 }).n;
    const calcRows = [];
    for (const plan of ['max', 'pro']) {
      const P = plan === 'max' ? 'Max' : 'Pro';
      for (const [kind, key, label] of [['bulan pertama', 'intro_', 'harga diskon (pelanggan baru)'], ['bulanan', 'price_', 'harga normal (perpanjangan)']]) {
        const n = Number(lineN(plan, kind)), unit = setv[key + plan] || 0;
        calcRows.push(`<tr><td>${P} · ${label}</td><td class="n">${rp(unit)} × ${num(n)} = <b>${rp(unit * n)}</b></td></tr>`);
      }
      const yn = Number(lineN(plan, 'tahunan'));
      if (yn) calcRows.push(`<tr><td>${P} · tahunan</td><td class="n">${rp(setv['yearly_' + plan] || 0)} × ${num(yn)} = <b>${rp((setv['yearly_' + plan] || 0) * yn)}</b></td></tr>`);
    }
    const lines = calcRows.join('');
    const profitCard = `<div class="card" style="margin-bottom:14px"><h3>Estimasi keuntungan ${pf.days} hari terakhir</h3>
      <p class="hint">Perkiraan pendapatan langganan dikurangi potongan Google dan biaya AI. Bukan laporan keuangan.</p>
      <div class="grid g2"><div><div class="kpi"><div class="v ${Number(pf.profit) < 0 ? 'down' : 'up'}">${Number(pf.profit) < 0 ? '−' : ''}${rp(Math.abs(pf.profit))}</div><div class="l">Estimasi keuntungan</div></div>
        <p class="hint" style="margin-top:10px;line-height:1.5">Rumusnya harga × jumlah pembayaran. Pembayaran pertama pelanggan baru memakai harga diskon. Belum termasuk donasi Traktir Matcha (tidak tercatat di server), pajak, dan pengembalian dana. Langganan hadiah tidak punya pendapatan. Harga dan potongan bisa diubah di <a href="#rilis">Rilis dan pengaturan</a>. Ringkasan sepanjang waktu ada di <a href="#keuangan">Keuangan</a>.</p></div>
        <div class="tablewrap"><table>${lines}
          <tr><td><b>Pendapatan kotor</b></td><td class="n"><b>${rp(pf.gross)}</b></td></tr>
          <tr><td>− Potongan Google ${num(pf.fee_percent)}%</td><td class="n">${rp(pf.fee)}</td></tr>
          <tr><td><b>Pendapatan bersih</b></td><td class="n"><b>${rp(pf.net)}</b></td></tr>
          <tr><td>− Biaya AI (${num(pf.ai_calls)} permintaan)</td><td class="n">${rp(pf.ai_cost)}</td></tr>
          ${Number(pf.gift_accounts) ? `<tr><td class="hint">${chip('am', 'Gratis')} ${num(pf.gift_accounts)} akun hadiah: pendapatan Rp0, biaya AI-nya (${rp(pf.gift_ai_cost)}) tetap ikut dihitung di atas</td><td></td></tr>` : ''}</table></div></div></div>`;
    return `<h1>Ringkasan</h1><p class="sub">Angka utama. Hari dihitung WIB. Biaya AI menghitung semua akun, termasuk akun uji dan sistem.</p>
      ${profitCard}
      <div class="grid g4" style="margin-bottom:14px">
        <div class="card kpi"><div class="v">${num(o.signups_total)}</div><div class="l">Pendaftar total</div><div class="d up">+${num(o.signups_today)} hari ini</div></div>
        <div class="card kpi"><div class="v">${num(Number(o.pro) + Number(o.max))}</div><div class="l">Pro / Max aktif</div><div class="d">${num(o.pro)} Pro · ${num(o.max)} Max</div></div>
        <div class="card kpi"><div class="v">${rp(t)}</div><div class="l">Biaya AI hari ini</div><div class="d ${delta != null && delta > 0 ? 'down' : 'up'}">${delta == null ? '—' : (delta > 0 ? '+' : '') + delta + '% dari kemarin'}</div></div>
        <div class="card kpi"><div class="v">${num(o.ai_calls_today)}</div><div class="l">Panggilan AI hari ini</div><div class="d">cache ${o.cache_ratio_today == null ? '—' : Math.round(o.cache_ratio_today * 100) + '%'}</div></div>
      </div>
      <div class="tl">${rangeChips}</div>
      <div class="grid g2">
        <div class="card"><h3>Pendaftar per hari</h3><p class="hint">Ketuk batang untuk rinciannya</p>${chart('su', su.map((r) => ({ d: String(r.day).slice(0, 10), lab: dayLabel(r.day), aria: longDay(String(r.day).slice(0, 10)), v: Number(r.n) })), (v) => num(v), (it, i) => `<b>${esc(longDay(it[i].d))}</b>: ${num(it[i].v)} pendaftar${deltaText(it, i, num)}`)}</div>
        <div class="card"><h3>Biaya AI per hari</h3><p class="hint">Ketuk batang untuk rinciannya</p>${chart('co', co.map((r) => ({ d: String(r.day).slice(0, 10), lab: dayLabel(r.day), aria: longDay(String(r.day).slice(0, 10)), v: Number(r.cost_idr), req: Number(r.requests) })), (v) => (v >= 1000 ? (v / 1000).toFixed(1) + 'rb' : String(Math.round(v))), (it, i) => `<b>${esc(longDay(it[i].d))}</b>: ${rp(it[i].v)} · ${num(it[i].req)} permintaan${deltaText(it, i, rp)}`)}</div>
      </div>
      <div class="card" style="margin-top:14px"><h3>Yang sedang aktif</h3><div class="tablewrap"><table>
        <tr><td>Pengumuman berlangsung</td><td>${Number(o.announcements_active) ? chip('red', o.announcements_active + ' aktif') : chip('gr', 'tidak ada')}</td><td class="n"><a href="#pengumuman">Buka</a></td></tr>
        <tr><td>Versi terbaru / minimum</td><td>${chip('gr', (rel.latest_version || '?') + (rel.latest_build ? '+' + rel.latest_build : '') + ' / ' + (rel.minimum_required_version || '?'))}</td><td class="n"><a href="#rilis">Buka</a></td></tr>
        <tr><td>Fitur menyala</td><td>${(o.flags_on || []).map((f) => chip('mu', f)).join(' ')}</td><td class="n"><a href="#rilis">Buka</a></td></tr></table></div></div>`;
  }


  // ------------------------------------------------------------------ Pendaftar
  const SG_KEY = 'admin-signup-prefs';
  const SG_DEFAULT = {
    series: { type: 'bar', range: '14', day: '' },
    weekday: { type: 'bar', range: 'all', metric: 'total' },
    hour: { type: 'bar', range: 'all', metric: 'total', dow: '' },
  };
  let sg = (() => {
    try { const v = JSON.parse(localStorage.getItem(SG_KEY) || 'null'); if (v && v.series && v.weekday && v.hour) return v; } catch (e) { /* none saved */ }
    return JSON.parse(JSON.stringify(SG_DEFAULT));
  })();
  const sgSave = () => { try { localStorage.setItem(SG_KEY, JSON.stringify(sg)); localStorage.setItem(AI_KEY, JSON.stringify(aip)); } catch (e) { /* private window */ } };
  const prefOf = (c) => (String(c).startsWith('ai-') ? aip[String(c).slice(3)] : sg[c]);
  const todayWib = () => new Date().toLocaleDateString('sv-SE', { timeZone: 'Asia/Jakarta' });
  const addDays = (d, n) => { const t = new Date(d + 'T00:00:00Z'); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };
  const rangeFrom = (r) => (r === 'all' ? null : addDays(todayWib(), -(Number(r) - 1)));
  const DOW_SHORT = ['Sen', 'Sel', 'Rab', 'Kam', 'Jum', 'Sab', 'Min'];
  const DOW_LONG = ['Senin', 'Selasa', 'Rabu', 'Kamis', 'Jumat', 'Sabtu', 'Minggu'];
  const avgFmt = (v) => Number(v).toLocaleString('id-ID', { maximumFractionDigits: 1 });

  function sgControls(c, prefs, ranges, opts) {
    const chips = (act, cur, list) => list.map(([v, t]) => `<button data-act="${act}" data-c="${c}" data-v="${v}" class="${String(cur) === String(v) ? 'on' : ''}">${t}</button>`).join('');
    return `<div class="tl" style="margin-bottom:8px">${chips('sg-type', prefs.type, [['bar', 'Batang'], ['line', 'Garis']])}<span class="sep"></span>${chips('sg-range', prefs.range, ranges)}${opts && opts.metric ? '<span class="sep"></span>' + chips('sg-metric', prefs.metric, [['total', 'Jumlah'], ['avg', 'Rata-rata per hari']]) : ''}</div>`;
  }

  async function pgPendaftar() {
    const today = todayWib();
    const oneDay = sg.series.range === 'day';
    const day = sg.series.day || today;
    const sFrom = oneDay ? day : rangeFrom(sg.series.range);
    const [ser, wd, hr] = await Promise.all([
      rpc('admin_signups_series', { p_from: sFrom, p_to: oneDay ? day : null, p_bucket: oneDay ? 'hour' : 'day' }),
      rpc('admin_signups_by_weekday', { p_from: rangeFrom(sg.weekday.range), p_to: null }),
      rpc('admin_signups_by_hour', { p_from: rangeFrom(sg.hour.range), p_to: null, p_dow: sg.hour.dow ? Number(sg.hour.dow) : null }),
    ]);

    // 1. per day, or per hour of one day
    const sItems = ser.map((r) => oneDay
      ? { lab: r.label, aria: 'Jam ' + r.label, v: Number(r.n), hour: r.label }
      : { lab: dayLabel(r.label), aria: longDay(r.label), v: Number(r.n), d: r.label });
    const sTotal = sItems.reduce((a, i) => a + i.v, 0);
    const sDetail = (it, i) => oneDay
      ? `<b>Jam ${esc(it[i].hour)}.00–${esc(it[i].hour)}.59</b>: ${num(it[i].v)} pendaftar${i > 0 ? ' · ' + (it[i].v - it[i - 1].v >= 0 ? '+' : '−') + num(Math.abs(it[i].v - it[i - 1].v)) + ' dari jam sebelumnya' : ''}`
      : `<b>${esc(longDay(it[i].d))}</b>: ${num(it[i].v)} pendaftar${deltaText(it, i, num)}`;
    const sRanges = [['day', 'Sehari (per jam)'], ['7', '7 hari'], ['14', '14 hari'], ['30', '30 hari'], ['all', 'Semua']];
    const dayPicker = oneDay ? `<div class="field" style="max-width:220px"><label>Tanggal</label><input type="date" data-act="sg-day" data-c="series" value="${esc(day)}" max="${esc(today)}"></div>` : '';
    const sPeak = sItems.reduce((m, i) => (i.v > m.v ? i : m), sItems[0] || { v: 0, lab: '' });

    // 2. by weekday
    const wMetric = sg.weekday.metric;
    const wItems = wd.map((r) => ({ lab: DOW_SHORT[r.dow - 1], aria: DOW_LONG[r.dow - 1], v: wMetric === 'avg' ? (r.days ? Number(r.n) / r.days : 0) : Number(r.n), n: Number(r.n), days: r.days, name: DOW_LONG[r.dow - 1] }));
    const wTop = wItems.reduce((m, i) => (i.v > m.v ? i : m), wItems[0]);
    const wDetail = (it, i) => `<b>${esc(it[i].name)}</b>: ${num(it[i].n)} pendaftar dari ${num(it[i].days)} hari ${esc(it[i].name)} · rata-rata ${avgFmt(it[i].days ? it[i].n / it[i].days : 0)} per hari`;

    // 3. by hour
    const hMetric = sg.hour.metric;
    const hItems = hr.map((r) => ({ lab: String(r.hour).padStart(2, '0'), aria: 'Jam ' + String(r.hour).padStart(2, '0'), v: hMetric === 'avg' ? (r.days ? Number(r.n) / r.days : 0) : Number(r.n), n: Number(r.n), days: r.days, hour: String(r.hour).padStart(2, '0') }));
    const hTop = hItems.reduce((m, i) => (i.v > m.v ? i : m), hItems[0]);
    const hDetail = (it, i) => `<b>Jam ${esc(it[i].hour)}.00–${esc(it[i].hour)}.59</b>: ${num(it[i].n)} pendaftar${it[i].days ? ` dari ${num(it[i].days)} hari · rata-rata ${avgFmt(it[i].n / it[i].days)} per hari` : ''}`;
    const hRanges = [['7', '7 hari'], ['14', '14 hari'], ['30', '30 hari'], ['90', '90 hari'], ['all', 'Semua']];
    const wRanges = [['14', '14 hari'], ['30', '30 hari'], ['90', '90 hari'], ['all', 'Semua']];
    const fmtVal = (metric) => (metric === 'avg' ? avgFmt : (v) => num(v));

    return `<h1>Pendaftar</h1><p class="sub">Kapan orang mendaftar. Hari dan jam dihitung WIB. Ketuk batang atau titik untuk rinciannya; pengaturan tersimpan di browser ini.</p>
      <div class="card" style="margin-bottom:14px"><h3>Pendaftar ${oneDay ? 'per jam' : 'per hari'}</h3>
        <p class="hint">${oneDay ? 'Jam demi jam pada satu hari' : 'Satu batang per hari'} · total ${num(sTotal)}${sItems.length && sPeak.v ? ` · tertinggi ${esc(oneDay ? 'jam ' + sPeak.lab : longDay(sPeak.d))} (${num(sPeak.v)})` : ''}</p>
        ${sgControls('series', sg.series, sRanges)}${dayPicker}
        ${chart('sgS', sItems, (v) => num(v), sDetail, { type: sg.series.type, noNow: oneDay })}</div>
      <div class="grid g2">
        <div class="card"><h3>Menurut hari dalam seminggu</h3><p class="hint">Semua tanggal digabung${wTop && wTop.v ? ` · paling ramai ${esc(wTop.name)}` : ''}</p>
          ${sgControls('weekday', sg.weekday, wRanges, { metric: true })}
          ${chart('sgW', wItems, fmtVal(wMetric), wDetail, { type: sg.weekday.type, sel: wItems.indexOf(wTop), noNow: true })}</div>
        <div class="card"><h3>Menurut jam</h3><p class="hint">Semua tanggal digabung, jam 00 sampai 23${hTop && hTop.v ? ` · paling ramai jam ${esc(hTop.hour)}.00` : ''}</p>
          ${sgControls('hour', sg.hour, hRanges, { metric: true })}
          <div class="field" style="max-width:220px;margin:0 0 8px"><label>Hanya hari</label><select data-act="sg-dow" data-c="hour"><option value="">Semua hari</option>${DOW_LONG.map((n, i) => `<option value="${i + 1}" ${String(sg.hour.dow) === String(i + 1) ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
          ${chart('sgH', hItems, fmtVal(hMetric), hDetail, { type: sg.hour.type, sel: hItems.indexOf(hTop), noNow: true })}</div>
      </div>`;
  }


  // ------------------------------------------------------------------ Analisis AI
  const AI_KEY = 'admin-ai-prefs';
  const AI_DEFAULT = {
    tab: 'all', metric: 'calls', fn: '', account: '',
    series: { type: 'bar', range: '14', day: '' },
    weekday: { type: 'bar', range: 'all', metric: 'total' },
    hour: { type: 'bar', range: 'all', metric: 'total', dow: '' },
    list: { tier: 'all', sort: 'calls', range: '30', q: '', page: 0 },
  };
  let aip = (() => {
    try { const v = JSON.parse(localStorage.getItem(AI_KEY) || 'null'); if (v && v.series && v.weekday && v.hour && v.list) return v; } catch (e) { /* none saved */ }
    return JSON.parse(JSON.stringify(AI_DEFAULT));
  })();
  const AI_FUNCTIONS = ['ai-chat', 'quick-add-categorize', 'category-icon-suggest', 'receipt-analyze', 'mutation-pdf-parse', 'scan-categorize', 'business-sale-parse'];
  const rpShort = (v) => (v >= 1e6 ? (v / 1e6).toFixed(1) + 'jt' : v >= 1000 ? (v / 1000).toFixed(1) + 'rb' : String(Math.round(v)));
  const PAGE_SIZE = 50;

  const tierBadges = (r) => `${tierChip(r.subscription_type)}${r.is_gift ? ' ' + chip('am', 'Gratis') : ''}${r.is_system ? ' ' + chip('mu', 'Uji/sistem') : ''}${isPotential(r) ? ' ' + chip('bl', 'Potensial') : ''}`;
  // a free (not gifted, not system) account that uses AI a lot: a likely buyer
  const isPotential = (r) => r.subscription_type === 'free' && !r.is_gift && !r.is_system && ((Number(r.active_days) >= 3 && Number(r.calls) >= 15) || Number(r.max_day_calls) >= 5);

  async function pgAnalisis() {
    const tabs = [['all', 'Semua pengguna'], ['user', 'Per pengguna'], ['list', 'Daftar pengguna']].map(([k, t]) => `<button data-act="ai-tab" data-v="${k}" class="${aip.tab === k ? 'on' : ''}">${t}</button>`).join('');
    const metricChips = [['calls', 'Hit'], ['cost', 'Biaya']].map(([k, t]) => `<button data-act="ai-metric" data-v="${k}" class="${aip.metric === k ? 'on' : ''}">${t}</button>`).join('');
    const fnSel = `<select data-act="ai-fn"><option value="">Semua fitur</option>${AI_FUNCTIONS.map((f) => `<option ${aip.fn === f ? 'selected' : ''}>${f}</option>`).join('')}</select>`;
    const head = `<h1>Analisis AI</h1><p class="sub">Pemakaian AI: berapa hit, berapa biayanya, kapan, dan siapa yang paling aktif. Semua akun dihitung. Hari dan jam WIB; pengaturan tersimpan di browser ini.</p>
      <div class="tl">${tabs}<span style="flex:1"></span>${aip.tab === 'list' ? '' : metricChips}${fnSel}</div>`;
    if (aip.tab === 'list') return head + (await aiList());
    if (aip.tab === 'user') return head + (await aiUser());
    return head + (await aiCharts(null));
  }

  // ---- charts + written summary for one scope (null = everybody)
  async function aiCharts(account) {
    const today = todayWib();
    const oneDay = aip.series.range === 'day';
    const day = aip.series.day || today;
    const fn = aip.fn || null;
    const [ser, wd, hr, sum] = await Promise.all([
      rpc('admin_ai_series', { p_account: account, p_from: oneDay ? day : rangeFrom(aip.series.range), p_to: oneDay ? day : null, p_bucket: oneDay ? 'hour' : 'day', p_function: fn }),
      rpc('admin_ai_by_weekday', { p_account: account, p_from: rangeFrom(aip.weekday.range), p_to: null, p_function: fn }),
      rpc('admin_ai_by_hour', { p_account: account, p_from: rangeFrom(aip.hour.range), p_to: null, p_dow: aip.hour.dow ? Number(aip.hour.dow) : null, p_function: fn }),
      rpc('admin_ai_summary', { p_account: account, p_from: rangeFrom(aip.series.range === 'day' ? '14' : aip.series.range), p_to: null, p_function: fn }),
    ]);
    const isCost = aip.metric === 'cost';
    const fmtV = (v) => (isCost ? rpShort(v) : num(v));
    const fmtAvg = (v) => (isCost ? rpShort(v) : avgFmt(v));
    const both = (calls, cost) => `${num(calls)} hit · ${rp(cost)}`;
    const pick = (calls, cost) => (isCost ? Number(cost) : Number(calls));

    const sItems = ser.map((r) => oneDay
      ? { lab: r.label, aria: 'Jam ' + r.label, v: pick(r.calls, r.cost_idr), calls: Number(r.calls), cost: Number(r.cost_idr), hour: r.label }
      : { lab: dayLabel(r.label), aria: longDay(r.label), v: pick(r.calls, r.cost_idr), calls: Number(r.calls), cost: Number(r.cost_idr), d: r.label });
    const sTotalCalls = sItems.reduce((a, i) => a + i.calls, 0), sTotalCost = sItems.reduce((a, i) => a + i.cost, 0);
    const sDetail = (it, i) => `<b>${oneDay ? 'Jam ' + esc(it[i].hour) + '.00–' + esc(it[i].hour) + '.59' : esc(longDay(it[i].d))}</b>: ${both(it[i].calls, it[i].cost)}${i > 0 ? ' · ' + (it[i].v - it[i - 1].v >= 0 ? '+' : '−') + (isCost ? rp(Math.abs(it[i].v - it[i - 1].v)) : num(Math.abs(it[i].v - it[i - 1].v))) + (oneDay ? ' dari jam sebelumnya' : ' dari hari sebelumnya') : ''}`;
    const sRanges = [['day', 'Sehari (per jam)'], ['7', '7 hari'], ['14', '14 hari'], ['30', '30 hari'], ['all', 'Semua']];
    const dayPicker = oneDay ? `<div class="field" style="max-width:220px"><label>Tanggal</label><input type="date" data-act="sg-day" data-c="ai-series" value="${esc(day)}" max="${esc(today)}"></div>` : '';

    const wMetric = aip.weekday.metric;
    const wItems = wd.map((r) => ({ lab: DOW_SHORT[r.dow - 1], aria: DOW_LONG[r.dow - 1], v: wMetric === 'avg' ? (r.days ? pick(r.calls, r.cost_idr) / r.days : 0) : pick(r.calls, r.cost_idr), calls: Number(r.calls), cost: Number(r.cost_idr), days: r.days, name: DOW_LONG[r.dow - 1] }));
    const wTop = wItems.reduce((m, i) => (i.v > m.v ? i : m), wItems[0]);
    const wDetail = (it, i) => `<b>${esc(it[i].name)}</b>: ${both(it[i].calls, it[i].cost)} dari ${num(it[i].days)} hari ${esc(it[i].name)} · rata-rata ${avgFmt(it[i].days ? it[i].calls / it[i].days : 0)} hit dan ${rp(it[i].days ? it[i].cost / it[i].days : 0)} per hari`;

    const hMetric = aip.hour.metric;
    const hItems = hr.map((r) => ({ lab: String(r.hour).padStart(2, '0'), aria: 'Jam ' + String(r.hour).padStart(2, '0'), v: hMetric === 'avg' ? (r.days ? pick(r.calls, r.cost_idr) / r.days : 0) : pick(r.calls, r.cost_idr), calls: Number(r.calls), cost: Number(r.cost_idr), days: r.days, hour: String(r.hour).padStart(2, '0') }));
    const hTop = hItems.reduce((m, i) => (i.v > m.v ? i : m), hItems[0]);
    const hDetail = (it, i) => `<b>Jam ${esc(it[i].hour)}.00–${esc(it[i].hour)}.59</b>: ${both(it[i].calls, it[i].cost)}${it[i].days ? ` dari ${num(it[i].days)} hari · rata-rata ${avgFmt(it[i].calls / it[i].days)} hit dan ${rp(it[i].cost / it[i].days)} per hari` : ''}`;
    const wRanges = [['14', '14 hari'], ['30', '30 hari'], ['90', '90 hari'], ['all', 'Semua']];
    const hRanges = [['7', '7 hari'], ['14', '14 hari'], ['30', '30 hari'], ['90', '90 hari'], ['all', 'Semua']];

    return aiSummaryCard(sum, account) + `
      <div class="card" style="margin-bottom:14px"><h3>${isCost ? 'Biaya' : 'Hit'} ${oneDay ? 'per jam' : 'per hari'}</h3>
        <p class="hint">${oneDay ? 'Jam demi jam pada satu hari' : 'Satu batang per hari'} · total ${num(sTotalCalls)} hit, ${rp(sTotalCost)}</p>
        ${sgControls('ai-series', aip.series, sRanges)}${dayPicker}
        ${chart('aiS', sItems, fmtV, sDetail, { type: aip.series.type, noNow: oneDay })}</div>
      <div class="grid g2">
        <div class="card"><h3>Menurut hari dalam seminggu</h3><p class="hint">Semua tanggal digabung${wTop && wTop.v ? ` · paling ${isCost ? 'mahal' : 'ramai'} ${esc(wTop.name)}` : ''}</p>
          ${sgControls('ai-weekday', aip.weekday, wRanges, { metric: true })}
          ${chart('aiW', wItems, wMetric === 'avg' ? fmtAvg : fmtV, wDetail, { type: aip.weekday.type, sel: wItems.indexOf(wTop), noNow: true })}</div>
        <div class="card"><h3>Menurut jam</h3><p class="hint">Semua tanggal digabung, jam 00 sampai 23${hTop && hTop.v ? ` · paling ${isCost ? 'mahal' : 'ramai'} jam ${esc(hTop.hour)}.00` : ''}</p>
          ${sgControls('ai-hour', aip.hour, hRanges, { metric: true })}
          <div class="field" style="max-width:220px;margin:0 0 8px"><label>Hanya hari</label><select data-act="sg-dow" data-c="ai-hour"><option value="">Semua hari</option>${DOW_LONG.map((n, i) => `<option value="${i + 1}" ${String(aip.hour.dow) === String(i + 1) ? 'selected' : ''}>${n}</option>`).join('')}</select></div>
          ${chart('aiH', hItems, hMetric === 'avg' ? fmtAvg : fmtV, hDetail, { type: aip.hour.type, sel: hItems.indexOf(hTop), noNow: true })}</div>
      </div>`;
  }

  function aiSummaryCard(sm, account) {
    const days = Number(sm.days_in_range) || 1, calls = Number(sm.calls), cost = Number(sm.cost_idr), aDays = Number(sm.active_days);
    const users = Number(sm.active_users);
    const kpi = (v, l) => `<div class="card kpi"><div class="v">${v}</div><div class="l">${l}</div></div>`;
    const rows = [
      ['Hit per hari (seluruh rentang)', avgFmt(calls / days)],
      ['Hit per hari aktif', avgFmt(aDays ? calls / aDays : 0)],
      ['Biaya per hari (seluruh rentang)', rp(cost / days)],
      ['Biaya per hari aktif', rp(aDays ? cost / aDays : 0)],
      ['Biaya rata-rata per hit', rp(calls ? cost / calls : 0)],
      ['Hari aktif', `${num(aDays)} dari ${num(days)} hari`],
      ...(account ? [] : [['Pengguna aktif', num(users)], ['Hit rata-rata per pengguna aktif', avgFmt(users ? calls / users : 0)], ['Biaya rata-rata per pengguna aktif', rp(users ? cost / users : 0)]]),
      ['Hit gagal (ada pesan error)', `${num(sm.errors)}${calls ? ' (' + avgFmt((Number(sm.errors) / calls) * 100) + '%)' : ''}`],
    ];
    const pd = sm.peak_day, pc = sm.peak_cost_day, ph = sm.peak_hour, pw = sm.peak_weekday;
    const reads = [];
    if (pd && Number(pd.calls)) reads.push(`Hari paling ramai: <b>${esc(longDay(String(pd.day)))}</b> dengan ${num(pd.calls)} hit${pc && String(pc.day) !== String(pd.day) ? `; hari paling mahal: <b>${esc(longDay(String(pc.day)))}</b> (${rp(pc.cost_idr)})` : ` (${rp(pd.cost_idr)})`}.`);
    if (pw && Number(pw.calls)) reads.push(`Paling sering dipakai pada hari <b>${esc(DOW_LONG[pw.dow - 1])}</b> (${num(pw.calls)} hit di seluruh rentang).`);
    if (ph && Number(ph.calls)) reads.push(`Jam tersibuk: <b>${String(ph.hour).padStart(2, '0')}.00</b> (${num(ph.calls)} hit).`);
    const fns = (sm.functions || []).map((f) => `<tr><td>${esc(f.fn)}</td><td class="n">${num(f.calls)}</td><td class="n">${calls ? avgFmt((Number(f.calls) / calls) * 100) + '%' : '—'}</td><td class="n">${rp(f.cost_idr)}</td><td class="n">${cost ? avgFmt((Number(f.cost_idr) / cost) * 100) + '%' : '—'}</td></tr>`).join('');
    return `<div class="card" style="margin-bottom:14px"><h3>Rangkuman${account ? ' pengguna ini' : ' semua pengguna'}</h3>
      <p class="hint">${esc(String(sm.from))} sampai ${esc(String(sm.to))}${aip.fn ? ' · fitur ' + esc(aip.fn) : ''}. Rentang mengikuti pilihan grafik pertama di bawah (mode sehari dihitung 14 hari).</p>
      <div class="grid g4" style="margin-bottom:12px">${kpi(num(calls), 'Total hit')}${kpi(rp(cost), 'Total biaya')}${kpi(rp(calls ? cost / calls : 0), 'Biaya per hit')}${kpi(account ? num(aDays) + ' hari' : num(users), account ? 'Hari aktif' : 'Pengguna aktif')}</div>
      <div class="grid g2"><div class="tablewrap"><table>${rows.map(([a, b]) => `<tr><td>${a}</td><td class="n"><b>${b}</b></td></tr>`).join('')}</table></div>
        <div><p style="margin:0 0 8px;font-weight:700">Cara membacanya</p>${reads.length ? reads.map((r) => `<p class="hint" style="margin:0 0 6px;line-height:1.5">${r}</p>`).join('') : '<p class="hint">Belum ada pemakaian di rentang ini.</p>'}
          <div class="tablewrap" style="margin-top:8px"><table><tr><th>Fitur</th><th class="n">Hit</th><th class="n">%</th><th class="n">Biaya</th><th class="n">%</th></tr>${fns || '<tr><td colspan="5" class="hint">Kosong.</td></tr>'}</table></div></div></div></div>`;
  }

  // ---- one chosen account
  async function aiUser() {
    const quick = aip.account ? [] : await rpc('admin_ai_users', { p_from: rangeFrom('30'), p_to: null, p_tier: 'all', p_q: null, p_sort: 'calls', p_limit: 10, p_offset: 0, p_function: null });
    const res = aip.uq ? await rpc('admin_find_users', { p_q: aip.uq }) : [];
    const picker = `<div class="card" style="margin-bottom:14px"><h3>Pilih pengguna</h3>
      <div class="searchrow"><input id="aiq" placeholder="email atau sebagian email" value="${esc(aip.uq || '')}"><button class="btn" data-act="ai-usearch">Cari</button><button class="btn sec" data-act="unmask">${unmask ? 'Sembunyikan email' : 'Tampilkan email'}</button></div>
      ${res.length ? `<div class="tablewrap" style="margin-top:10px"><table>${res.map((u) => `<tr><td>${who(u.email)}</td><td>${tierChip(u.subscription_type)}${u.tier_source === 'gift' ? ' ' + chip('am', 'Gratis') : ''}</td><td class="n"><button class="btn sm" data-act="ai-pick" data-email="${esc(u.email)}">Analisis</button></td></tr>`).join('')}</table></div>` : ''}
      ${quick.length ? `<p class="hint" style="margin:12px 0 6px">Paling aktif 30 hari terakhir</p><div class="tablewrap"><table>${quick.map((r) => `<tr><td class="mono">${who(r.account_key)}</td><td>${tierBadges(r)}</td><td class="n">${num(r.calls)} hit</td><td class="n"><button class="btn sm" data-act="ai-pick" data-email="${esc(r.account_key)}">Analisis</button></td></tr>`).join('')}</table></div>` : ''}</div>`;
    if (!aip.account) return picker + '<div class="card"><p class="hint">Pilih pengguna di atas untuk melihat grafik pemakaiannya.</p></div>';
    const info = (await rpc('admin_ai_users', { p_from: null, p_to: null, p_tier: 'all', p_q: aip.account, p_sort: 'calls', p_limit: 5, p_offset: 0, p_function: null })).find((r) => r.account_key === aip.account.toLowerCase());
    const header = info ? `<div class="card" style="margin-bottom:14px"><div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap"><b class="mono">${who(info.account_key)}</b>${tierBadges(info)}<span style="flex:1"></span><button class="btn sec sm" data-act="ai-clear">Ganti pengguna</button></div>
      <p class="hint" style="margin:8px 0 0">Daftar ${when(info.registered_at)} · terakhir masuk ${when(info.last_sign_in_at)} · terakhir pakai AI ${when(info.last_call)} · sepanjang waktu ${num(info.calls)} hit, ${rp(info.cost_idr)}</p></div>` : `<div class="card" style="margin-bottom:14px"><b class="mono">${who(aip.account)}</b> <button class="btn sec sm" data-act="ai-clear">Ganti pengguna</button></div>`;
    return picker + header + (await aiCharts(aip.account));
  }

  // ---- everybody, with tier labels
  async function aiList() {
    const L = aip.list;
    const rows = await rpc('admin_ai_users', { p_from: rangeFrom(L.range), p_to: null, p_tier: L.tier, p_q: L.q || null, p_sort: L.sort, p_limit: PAGE_SIZE, p_offset: L.page * PAGE_SIZE, p_function: aip.fn || null });
    const total = rows.length ? Number(rows[0].total_count) : 0;
    const chips = (act, cur, list) => list.map(([v, t]) => `<button data-act="${act}" data-v="${v}" class="${String(cur) === String(v) ? 'on' : ''}">${t}</button>`).join('');
    const SORTS = [['calls', 'Hit terbanyak'], ['cost', 'Biaya terbesar'], ['active_days', 'Hari aktif terbanyak'], ['max_day', 'Hit terbanyak dalam sehari'], ['avg_cost', 'Biaya per hit tertinggi'], ['last_call', 'Terakhir pakai'], ['registered', 'Terbaru mendaftar']];
    const body = rows.map((r) => `<tr><td class="mono">${who(r.account_key)}</td><td>${tierBadges(r)}</td><td>${r.registered_at ? esc(String(r.registered_at).slice(0, 10)) : '—'}</td><td class="n">${num(r.calls)}</td><td class="n">${rp(r.cost_idr)}</td><td class="n">${Number(r.calls) ? rp(r.avg_cost_idr) : '—'}</td><td class="n">${num(r.active_days)}</td><td class="n">${num(r.max_day_calls)}</td><td>${r.last_call ? when(r.last_call) : '—'}</td><td class="n">${avgFmt(Number(r.share_cost) * 100)}%</td><td class="n"><button class="btn sm sec" data-act="ai-pick" data-email="${esc(r.account_key)}">Analisis</button></td></tr>`).join('');
    const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
    return `<div class="card"><h3>Daftar semua pengguna</h3>
      <p class="hint">Semua akun terdaftar dengan pemakaian AI-nya. <b>Potensial</b> = akun Free (bukan hadiah) yang sering memakai AI: aktif di minimal 3 hari dengan minimal 15 hit, atau pernah 5 hit atau lebih dalam sehari. Mereka calon pelanggan berbayar.</p>
      <div class="tl">${chips('ai-tier', L.tier, [['all', 'Semua paket'], ['free', 'Free'], ['pro', 'Pro'], ['max', 'Max'], ['gift', 'Gratis (hadiah)']])}<span class="sep"></span>${chips('ai-lrange', L.range, [['7', '7 hari'], ['30', '30 hari'], ['90', '90 hari'], ['all', 'Semua']])}</div>
      <div class="searchrow" style="margin-bottom:10px"><input id="aiq" placeholder="cari email" value="${esc(L.q || '')}"><select data-act="ai-sort">${SORTS.map(([v, t]) => `<option value="${v}" ${L.sort === v ? 'selected' : ''}>${t}</option>`).join('')}</select><button class="btn" data-act="ai-lsearch">Cari</button><button class="btn sec" data-act="unmask">${unmask ? 'Sembunyikan email' : 'Tampilkan email'}</button><button class="btn sec" data-act="ai-csv">Unduh CSV</button></div>
      <div class="tablewrap"><table><tr><th>Akun</th><th>Paket</th><th>Daftar</th><th class="n">Hit</th><th class="n">Biaya</th><th class="n">Biaya/hit</th><th class="n">Hari aktif</th><th class="n">Maks/hari</th><th>Terakhir</th><th class="n">Porsi biaya</th><th></th></tr>${body || '<tr><td colspan="11" class="hint">Tidak ada akun yang cocok.</td></tr>'}</table></div>
      <div class="searchrow" style="margin-top:10px;align-items:center"><span class="hint">${num(total)} akun · halaman ${L.page + 1} dari ${pages}</span><span style="flex:1"></span><button class="btn sec sm" data-act="ai-page" data-d="-1" ${L.page <= 0 ? 'disabled' : ''}>Sebelumnya</button><button class="btn sec sm" data-act="ai-page" data-d="1" ${L.page + 1 >= pages ? 'disabled' : ''}>Berikutnya</button></div></div>`;
  }
  async function aiCsv() {
    const L = aip.list;
    try {
      const rows = await rpc('admin_ai_users', { p_from: rangeFrom(L.range), p_to: null, p_tier: L.tier, p_q: L.q || null, p_sort: L.sort, p_limit: 2000, p_offset: 0, p_function: aip.fn || null });
      const head = ['email', 'paket', 'gratis', 'uji_sistem', 'potensial', 'daftar', 'hit', 'biaya_idr', 'biaya_per_hit_idr', 'hari_aktif', 'maks_hit_sehari', 'terakhir_pakai', 'porsi_biaya_persen'];
      const q = (v) => '"' + String(v ?? '').replace(/"/g, '""') + '"';
      const lines = rows.map((r) => [r.account_key, r.subscription_type, r.is_gift ? 'ya' : '', r.is_system ? 'ya' : '', isPotential(r) ? 'ya' : '', String(r.registered_at || '').slice(0, 10), r.calls, Math.round(r.cost_idr), Math.round(r.avg_cost_idr), r.active_days, r.max_day_calls, r.last_call || '', (Number(r.share_cost) * 100).toFixed(2)].map(q).join(','));
      const blob = new Blob([[head.map(q).join(','), ...lines].join('\n')], { type: 'text/csv;charset=utf-8' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob); a.download = 'pengguna-ai.csv'; document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
      toast(`${rows.length} akun diunduh.`);
    } catch (e) { fail(e); }
  }

  // ------------------------------------------------------------------ Pengumuman
  const KINDS = { gangguan: ['red', 'Gangguan'], info: ['bl', 'Info'], pembaruan: ['gr', 'Pembaruan'] };
  const FEATURES = [['ai', 'AI'], ['scan', 'Scan'], ['sync', 'Sinkron'], ['backup', 'Backup'], ['subscription', 'Langganan']];
  async function pgPengumuman() {
    const { data, error } = await sb.from('announcements').select('*').order('created_at', { ascending: false }).limit(50);
    if (error) throw error;
    const rows = data.map((a) => {
      const k = KINDS[a.kind] || ['mu', a.kind];
      const active = a.status === 'active';
      const canPush = active && a.send_push && !a.push_sent_at && a.audience === 'all' && !a.min_version && !a.max_version;
      return `<tr><td><b>${esc(a.title_id)}</b><br><span class="hint">${when(a.created_at)} · ${esc(a.kind)}${a.show_modal ? ' · modal' : ''}${a.features.length ? ' · ' + esc(a.features.join(', ')) : ''}${a.push_sent_at ? ' · push terkirim' : ''}</span></td>
        <td>${active ? chip(k[0], active && a.kind === 'gangguan' ? 'Berlangsung' : k[1]) : chip('mu', 'Selesai')}</td>
        <td class="n"><div class="actions">${active ? `<button class="btn sm sec" data-act="ann-update" data-id="${a.id}">Kabar</button>` : ''}${canPush ? `<button class="btn sm sec" data-act="ann-push" data-id="${a.id}">Kirim push</button>` : ''}${active ? `<button class="btn sm" data-act="ann-resolve" data-id="${a.id}">Selesai</button>` : ''}</div></td></tr>`;
    }).join('');
    return `<h1>Pengumuman</h1><p class="sub">Yang tampil ke user: modal, daftar Pengumuman, notifikasi, dan strip di layar fitur yang terdampak.</p>
      <div class="grid g2">
        <div class="card"><h3>Buat pengumuman</h3><p class="hint">Teks Indonesia dan Inggris wajib diisi.</p>
          <form id="annform">
          <div class="tl" id="annkind"><button type="button" class="on" data-kind="gangguan">Gangguan</button><button type="button" data-kind="info">Info</button><button type="button" data-kind="pembaruan">Pembaruan</button></div>
          <div class="field"><label>Judul (Indonesia)</label><input name="title_id" required maxlength="120"></div>
          <div class="field"><label>Isi (Indonesia)</label><textarea name="body_id" required maxlength="1000"></textarea></div>
          <div class="field"><label>Judul (English)</label><input name="title_en" required maxlength="120"></div>
          <div class="field"><label>Isi (English)</label><textarea name="body_en" required maxlength="1000"></textarea></div>
          <div class="field"><label>Fitur terdampak (muncul strip di layarnya)</label><div class="checks">${FEATURES.map(([k, t]) => `<label><input type="checkbox" name="feat" value="${k}">${t}</label>`).join('')}</div></div>
          <div class="field"><label>Untuk</label><select name="audience"><option value="all">Semua user</option><option value="free">Free</option><option value="pro">Pro</option><option value="max">Max</option><option value="paid">Berbayar (Pro+Max)</option></select></div>
          <div class="row2"><div class="field"><label>Versi app dari (opsional)</label><input name="min_version" placeholder="mis. 1.7.0"></div><div class="field"><label>Sampai (opsional)</label><input name="max_version" placeholder="mis. 1.8.0"></div></div>
          <div class="checks"><label><input type="checkbox" name="show_modal" checked>Tampilkan modal</label><label><input type="checkbox" name="send_push" id="sendpush">Kirim push (hanya “Semua user” tanpa batas versi)</label></div>
          <button class="btn" type="submit">Terbitkan</button></form></div>
        <div class="card"><h3>Daftar pengumuman</h3><p class="hint">Terbaru di atas</p><div class="tablewrap"><table><tr><th>Judul</th><th>Status</th><th></th></tr>${rows || '<tr><td colspan="3" class="hint">Belum ada pengumuman.</td></tr>'}</table></div></div>
      </div>`;
  }
  async function annSubmit(form) {
    const f = new FormData(form);
    const kind = $('#annkind .on').dataset.kind;
    const row = {
      kind, title_id: f.get('title_id').trim(), body_id: f.get('body_id').trim(),
      title_en: f.get('title_en').trim(), body_en: f.get('body_en').trim(),
      features: f.getAll('feat'), audience: f.get('audience'), show_modal: !!f.get('show_modal'), send_push: !!f.get('send_push'),
      min_version: f.get('min_version').trim() || null, max_version: f.get('max_version').trim() || null,
    };
    if (row.send_push && (row.audience !== 'all' || row.min_version || row.max_version)) return fail('Push hanya untuk “Semua user” tanpa batas versi.');
    if (!confirm(`Terbitkan “${row.title_id}” ke ${row.audience === 'all' ? 'semua user' : row.audience}${row.send_push ? ' dan kirim push' : ''}?`)) return;
    const { data, error } = await sb.from('announcements').insert(row).select().single();
    if (error) return fail(error);
    if (row.send_push) await sendPush(data.id, true);
    toast('Pengumuman terbit.'); route();
  }
  async function sendPush(id, quiet) {
    const { data: s } = await sb.auth.getSession();
    const res = await fetch(cfg.url + '/functions/v1/announce-push', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + s.session.access_token, apikey: cfg.anonKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ announcementId: id }),
    });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) return fail('Push gagal: ' + (j.error || res.status));
    if (!quiet) toast('Push terkirim.');
    if (!quiet) route();
  }
  async function annResolve(id) {
    if (!confirm('Tandai pengumuman ini selesai? Strip di layar fitur hilang dan user dapat kabar singkat.')) return;
    const { error } = await sb.from('announcements').update({ status: 'resolved' }).eq('id', id);
    if (error) return fail(error);
    toast('Ditandai selesai.'); route();
  }
  function annUpdateModal(id) {
    openModal(`<h3 style="margin:0 0 10px">Kabar baru</h3><p class="hint">Ditambahkan ke linimasa di halaman detail pengumuman.</p>
      <div class="field"><label>Indonesia</label><textarea id="upid" maxlength="500"></textarea></div>
      <div class="field"><label>English</label><textarea id="upen" maxlength="500"></textarea></div>
      <div class="actions"><button class="btn sec" data-act="close">Batal</button><button class="btn" data-act="ann-update-save" data-id="${id}">Simpan</button></div>`);
  }
  async function annUpdateSave(id) {
    const text_id = $('#upid').value.trim(), text_en = $('#upen').value.trim();
    if (!text_id || !text_en) return fail('Isi kedua bahasa.');
    const { data, error } = await sb.from('announcements').select('updates').eq('id', id).single();
    if (error) return fail(error);
    const updates = [...(data.updates || []), { at: new Date().toISOString(), text_id, text_en }];
    const r = await sb.from('announcements').update({ updates }).eq('id', id);
    if (r.error) return fail(r.error);
    closeModal(); toast('Kabar ditambahkan.'); route();
  }

  // ------------------------------------------------------------------ Pengguna
  let userQuery = '';
  async function pgPengguna() {
    const users = await rpc('admin_find_users', { p_q: userQuery });
    const rows = users.map((u) => `<tr><td>${who(u.email)}<br><span class="hint">daftar ${when(u.created_at)} · masuk ${when(u.last_sign_in_at)}</span></td><td>${tierChip(u.subscription_type)}</td><td>${u.tier_source === 'gift' ? chip('am', 'Gratis (hadiah)') : esc(u.tier_source || '—')}</td>
      <td class="n">${u.tier_source === 'play' ? '<span class="hint">dari Play</span>' : `<button class="btn sm sec" data-act="tier" data-email="${esc(u.email)}" data-type="${esc(u.subscription_type)}">Ubah</button>`}</td></tr>`).join('');
    return `<h1>Pengguna</h1><p class="sub">Cari akun dan ubah paketnya (hadiah). Paket yang berasal dari Google Play tidak bisa diubah di sini.</p>
      <div class="card"><div class="searchrow"><input id="uq" placeholder="email atau sebagian email" value="${esc(userQuery)}"><button class="btn" data-act="usearch">Cari</button><button class="btn sec" data-act="unmask">${unmask ? 'Sembunyikan email' : 'Tampilkan email'}</button></div>
      <div class="tablewrap" style="margin-top:12px"><table><tr><th>Akun</th><th>Paket</th><th>Sumber</th><th></th></tr>${rows || '<tr><td colspan="4" class="hint">Tidak ada hasil.</td></tr>'}</table></div>
      <p class="hint" style="margin:10px 0 0">Menampilkan 25 terbaru. Cari dengan email untuk akun tertentu.</p></div>`;
  }
  function tierModal(email, type) {
    openModal(`<h3 style="margin:0 0 6px">Ubah paket</h3><p class="hint">${esc(email)}</p>
      <div class="field"><label>Paket (hadiah)</label><select id="tiersel">${['free', 'pro', 'max'].map((t) => `<option value="${t}" ${t === type ? 'selected' : ''}>${t[0].toUpperCase() + t.slice(1)}</option>`).join('')}</select></div>
      <div class="actions"><button class="btn sec" data-act="close">Batal</button><button class="btn" data-act="tier-save" data-email="${esc(email)}">Simpan</button></div>`);
  }
  async function tierSave(email) {
    try { await rpc('admin_set_tier', { p_email: email, p_type: $('#tiersel').value }); closeModal(); toast('Paket diubah.'); route(); } catch (e) { fail(e); }
  }

  // ------------------------------------------------------------------ Biaya AI
  const cost = { days: 7, fn: '', hideOwn: true };
  async function pgBiaya() {
    const fn = cost.fn || null;
    const [perDay, perAcc, exp, accProfit] = await Promise.all([
      rpc('admin_ai_cost_per_day', { p_days: cost.days, p_function: fn }),
      rpc('admin_ai_cost_per_account', { p_days: cost.days, p_function: fn, p_hide_own: cost.hideOwn }),
      rpc('admin_expensive_calls', { p_min_idr: 20, p_limit: 30 }),
      rpc('admin_account_profit', { p_days: cost.days }),
    ]);
    const chips = [[1, 'Hari ini'], [7, '7 hari'], [30, '30 hari'], [90, '90 hari']].map(([d, t]) => `<button data-act="cost-days" data-v="${d}" class="${cost.days === d ? 'on' : ''}">${t}</button>`).join('');
    const total = perDay.reduce((s, r) => s + Number(r.cost_idr), 0), reqs = perDay.reduce((s, r) => s + Number(r.requests), 0);
    return `<h1>Biaya AI</h1><p class="sub">Dari tabel panggilan AI. Semua akun dihitung, termasuk akun uji dan sistem. Kurs Rp17.900 per USD.</p>
      <div class="tl">${chips}<span style="flex:1"></span>
        <select data-act="cost-fn"><option value="">Semua fitur</option>${['ai-chat', 'receipt-analyze', 'quick-add', 'scan', 'business-sale-parse'].map((f) => `<option ${cost.fn === f ? 'selected' : ''}>${f}</option>`).join('')}</select>
        <button data-act="cost-own" class="${cost.hideOwn ? 'on' : ''}">Sembunyikan akun saya</button><button data-act="unmask" class="${unmask ? 'on' : ''}">Email penuh</button></div>
      <div class="grid g3" style="margin-bottom:14px"><div class="card kpi"><div class="v">${rp(total)}</div><div class="l">Biaya ${cost.days} hari</div></div><div class="card kpi"><div class="v">${num(reqs)}</div><div class="l">Permintaan</div></div><div class="card kpi"><div class="v">${reqs ? rp(total / reqs) : '—'}</div><div class="l">Rata-rata per permintaan</div></div></div>
      <div class="grid g2">
        <div class="card"><h3>Per hari</h3><div class="tablewrap"><table><tr><th>Tanggal</th><th class="n">Permintaan</th><th class="n">USD</th><th class="n">Rupiah</th></tr>${[...perDay].reverse().slice(0, 31).map((r) => `<tr><td>${esc(String(r.day).slice(5))}</td><td class="n">${num(r.requests)}</td><td class="n">${usd(r.cost_usd)}</td><td class="n">${rp(r.cost_idr)}</td></tr>`).join('')}</table></div></div>
        <div class="card"><h3>Per akun</h3><p class="hint">${cost.days === 1 ? 'Hari ini' : cost.days + ' hari terakhir'} (hari ini WIB tidak dipisah)</p><div class="tablewrap"><table><tr><th>Akun</th><th class="n">Panggilan</th><th class="n">Rata-rata USD</th><th class="n">Rupiah</th></tr>${perAcc.slice(0, 25).map((r) => `<tr><td class="mono">${who(r.account_key)}</td><td class="n">${num(r.calls)}</td><td class="n">${usd(r.avg_usd)}</td><td class="n">${rp(r.cost_idr)}</td></tr>`).join('') || '<tr><td colspan="4" class="hint">Kosong.</td></tr>'}</table></div></div>
      </div>
      <div class="card" style="margin-top:14px"><h3>Untung per akun</h3><p class="hint">${cost.days === 1 ? 'Hari ini' : cost.days + ' hari terakhir'}. Pendapatan bersih adalah perkiraan setelah potongan Google. Akun hadiah (gratis) tidak punya pendapatan, jadi untungnya Rp0 dan diberi tanda; biayanya tetap dihitung di total.</p><div class="tablewrap"><table><tr><th>Akun</th><th>Paket</th><th class="n">Biaya AI</th><th class="n">Pendapatan bersih</th><th class="n">Untung</th></tr>${accProfit.slice(0, 30).map((r) => `<tr><td class="mono">${who(r.account_key)}${r.is_gift ? ' ' + chip('am', 'Gratis') : ''}${r.is_system ? ' ' + chip('mu', 'Uji/sistem') : ''}</td><td>${tierChip(r.subscription_type)}</td><td class="n">${rp(r.cost_idr)}</td><td class="n">${r.is_gift ? '—' : rp(r.net_idr)}</td><td class="n ${r.is_gift ? '' : Number(r.profit_idr) < 0 ? 'down' : 'up'}">${r.is_gift ? 'Rp0' : (Number(r.profit_idr) < 0 ? '−' : '') + rp(Math.abs(r.profit_idr))}</td></tr>`).join('') || '<tr><td colspan="5" class="hint">Kosong.</td></tr>'}</table></div></div>
      <div class="card" style="margin-top:14px"><h3>Panggilan mahal</h3><p class="hint">Biaya ≥ Rp20 per panggilan, 30 terbaru</p><div class="tablewrap"><table><tr><th>Waktu</th><th>Akun</th><th>Fungsi</th><th class="n">Cache</th><th class="n">Rupiah</th></tr>${exp.map((r) => `<tr><td>${when(r.created_at)}</td><td class="mono">${who(r.account_key)}</td><td>${esc(r.edge_function)}</td><td class="n">${r.cache_hit_ratio == null ? '—' : Math.round(r.cache_hit_ratio * 100) + '%'}</td><td class="n">${rp(r.cost_idr)}</td></tr>`).join('') || '<tr><td colspan="5" class="hint">Tidak ada.</td></tr>'}</table></div></div>`;
  }


  // ------------------------------------------------------------------ Keuangan
  async function aiBalance() {
    try {
      const { data: s2 } = await sb.auth.getSession();
      const res = await fetch(cfg.url + '/functions/v1/admin-ai-balance', {
        method: 'POST',
        headers: { Authorization: 'Bearer ' + s2.session.access_token, apikey: cfg.anonKey, 'Content-Type': 'application/json' },
        body: '{}',
      });
      const j = await res.json().catch(() => ({}));
      return res.ok ? j : { error: j.error || String(res.status) };
    } catch (e) { return { error: e.message || String(e) }; }
  }
  const ledgerRows = (list) => list.map((l) => `<tr><td>${esc(String(l.at))}<br><span class="hint">${esc(l.note || '')}</span></td><td class="n">${rp(l.amount_idr)}</td><td class="n"><button class="btn sm sec" data-act="ledger-del" data-id="${l.id}">Hapus</button></td></tr>`).join('') || '<tr><td colspan="3" class="hint">Belum ada catatan.</td></tr>';
  const ledgerForm = (kind, title, hint) => `<div class="card"><h3>${title}</h3><p class="hint">${hint}</p>
    <div class="row2"><div class="field"><label>Tanggal</label><input type="date" id="ld-${kind}" value="${esc(todayWib())}" max="${esc(todayWib())}"></div><div class="field"><label>Jumlah (Rp)</label><input id="la-${kind}" inputmode="numeric" placeholder="mis. 100000"></div></div>
    <div class="field"><label>Catatan (opsional)</label><input id="ln-${kind}" maxlength="120"></div>
    <button class="btn" data-act="ledger-add" data-kind="${kind}">Catat</button></div>`;

  async function pgKeuangan() {
    const [f, led, bal] = await Promise.all([rpc('admin_finance_summary'), rpc('admin_ledger_list'), aiBalance()]);
    const wd = led.filter((l) => l.kind === 'withdrawal'), tp = led.filter((l) => l.kind === 'ai_topup');
    const since = f.since ? new Date(f.since + 'T00:00:00').toLocaleDateString('id-ID', { day: 'numeric', month: 'long', year: 'numeric' }) : '—';
    const balCard = bal.error
      ? `<p class="hint">Saldo belum bisa diambil: ${esc(bal.error)}</p>`
      : (bal.balances || []).map((b) => `<div class="kpi"><div class="v">${esc(b.currency)} ${esc(b.total)}</div><div class="l">isi ulang ${esc(b.topped_up)} · bonus ${esc(b.granted)}${b.currency === 'USD' ? ' · sekitar ' + rp(Number(b.total) * 17900) : ''}</div></div>`).join('') + (bal.is_available ? '' : '<p class="warn">DeepSeek menyatakan saldo tidak cukup untuk memanggil API.</p>');
    const profitNeg = Number(f.profit) < 0;
    return `<h1>Keuangan</h1><p class="sub">Ringkasan sejak ${esc(since)} dan catatan uang masuk keluar yang kamu isi sendiri. Pendapatan adalah perkiraan dari langganan Play.</p>
      <div class="grid g2" style="margin-bottom:14px">
        <div class="card"><h3>Saldo DeepSeek sekarang</h3><p class="hint">Diambil langsung dari DeepSeek lewat server, kunci tidak keluar dari server.</p>${balCard}<button class="btn sec sm" data-act="reload" style="margin-top:10px">Muat ulang</button></div>
        <div class="card"><h3>Modal AI</h3><div class="tablewrap"><table>
          <tr><td>Total modal AI yang kamu tambahkan</td><td class="n"><b>${rp(f.ai_topups)}</b></td></tr>
          <tr><td>Biaya AI terpakai sejak ${esc(since)} (semua akun)</td><td class="n">${rp(f.ai_cost)}</td></tr>
          <tr><td class="hint">Selisih ini hanya pembanding kasar: biaya dihitung dari catatan panggilan, saldo asli ada di kiri.</td><td class="n">${rp(Number(f.ai_topups) - Number(f.ai_cost))}</td></tr></table></div></div>
      </div>
      <div class="card" style="margin-bottom:14px"><h3>Ringkasan sepanjang waktu</h3><div class="tablewrap"><table>
        <tr><td>Pendapatan kotor (perkiraan)</td><td class="n">${rp(f.gross)}</td></tr>
        <tr><td>− Potongan Google ${num(f.fee_percent)}%</td><td class="n">${rp(f.fee)}</td></tr>
        <tr><td><b>Pendapatan bersih</b></td><td class="n"><b>${rp(f.net)}</b></td></tr>
        <tr><td>− Biaya AI semua akun</td><td class="n">${rp(f.ai_cost)}</td></tr>
        <tr><td class="hint">${chip('am', 'Gratis')} termasuk biaya akun hadiah ${rp(f.ai_cost_gift)} (pendapatannya Rp0, biayanya tetap dihitung)</td><td></td></tr>
        <tr><td><b>Estimasi keuntungan total</b></td><td class="n ${profitNeg ? 'down' : 'up'}"><b>${profitNeg ? '−' : ''}${rp(Math.abs(f.profit))}</b></td></tr>
        <tr><td>− Keuntungan yang sudah diambil</td><td class="n">${rp(f.withdrawn)}</td></tr>
        <tr><td><b>Keuntungan yang belum diambil</b></td><td class="n"><b>${Number(f.available) < 0 ? '−' : ''}${rp(Math.abs(f.available))}</b></td></tr></table></div></div>
      <div class="grid g2">
        <div>${ledgerForm('withdrawal', 'Keuntungan diambil', 'Catat setiap kali kamu menarik keuntungan.')}
          <div class="card" style="margin-top:14px"><h3>Riwayat pengambilan</h3><div class="tablewrap"><table>${ledgerRows(wd)}</table></div></div></div>
        <div>${ledgerForm('ai_topup', 'Tambah modal AI', 'Catat setiap kali kamu mengisi saldo DeepSeek.')}
          <div class="card" style="margin-top:14px"><h3>Riwayat modal AI</h3><div class="tablewrap"><table>${ledgerRows(tp)}</table></div></div></div>
      </div>`;
  }
  async function ledgerAdd(kind) {
    const amount = Number(String($('#la-' + kind).value).replace(/[^0-9]/g, ''));
    if (!amount) return fail('Isi jumlahnya.');
    try {
      await rpc('admin_ledger_add', { p_kind: kind, p_at: $('#ld-' + kind).value || null, p_amount: amount, p_note: $('#ln-' + kind).value });
      toast('Tercatat.'); route();
    } catch (e) { fail(e); }
  }
  async function ledgerDel(id) {
    if (!confirm('Hapus catatan ini?')) return;
    try { await rpc('admin_ledger_delete', { p_id: Number(id) }); toast('Dihapus.'); route(); } catch (e) { fail(e); }
  }

  // ------------------------------------------------------------------ Kuota AI
  async function pgKuota() {
    return `<h1>Kuota AI</h1><p class="sub">Reset pemakaian harian. Aksi yang mengubah banyak akun minta konfirmasi dan dicatat di riwayat.</p>
      <div class="grid g2">
        <div class="card"><h3>Reset satu akun</h3><p class="hint">Pemakaian harian akun itu jadi 0.</p><div class="field"><label>Akun</label><input id="qemail" placeholder="email lengkap"></div><button class="btn" data-act="quota-one">Reset akun ini</button></div>
        <div class="card"><h3>Reset semua user</h3><p class="hint">Pemakaian akun dan perangkat semua orang jadi 0.</p><div class="warn">Memengaruhi semua akun. Butuh ketik RESET.</div><button class="btn dng" data-act="quota-all">Reset semua…</button></div>
      </div>`;
  }
  async function quotaOne() {
    const email = $('#qemail').value.trim();
    if (!email.includes('@')) return fail('Isi email lengkap.');
    if (!confirm('Reset kuota ' + email + '?')) return;
    try { const n = await rpc('admin_reset_quota_account', { p_email: email }); toast(n ? 'Kuota direset.' : 'Akun tidak ditemukan di tabel kuota.', !n); } catch (e) { fail(e); }
  }
  function quotaAllModal() {
    openModal(`<h3 style="margin:0 0 6px">Reset kuota AI semua user?</h3><p class="hint" style="line-height:1.5">Pemakaian harian SEMUA akun dan perangkat jadi 0. Tidak bisa dibatalkan. Ketik <b>RESET</b> untuk lanjut.</p>
      <input id="qconfirm" style="width:100%;margin-bottom:12px" placeholder="RESET" autocomplete="off">
      <div class="actions"><button class="btn sec" data-act="close">Batal</button><button class="btn dng" data-act="quota-all-do">Reset</button></div>`);
  }
  async function quotaAllDo() {
    try { const r = await rpc('admin_reset_quota_all', { p_confirm: $('#qconfirm').value.trim() }); closeModal(); toast(`Direset: ${r.accounts} akun, ${r.devices} perangkat.`); } catch (e) { fail(e); }
  }

  // ------------------------------------------------------------------ Rilis & pengaturan
  async function pgRilis() {
    const [rel, flags, params, audit, sets] = await Promise.all([rpc('admin_get_release'), rpc('admin_list_flags'), rpc('admin_list_parameters'), rpc('admin_audit_list', { p_limit: 15 }), rpc('admin_get_settings')]);
    const SET_LABEL = { price_pro: 'Harga Pro per bulan', price_max: 'Harga Max per bulan', intro_pro: 'Pro bulan pertama (diskon)', intro_max: 'Max bulan pertama (diskon)', yearly_pro: 'Pro per tahun', yearly_max: 'Max per tahun', google_fee_percent: 'Potongan Google (%)' };
    return `<h1>Rilis dan pengaturan</h1><p class="sub">Versi aplikasi, fitur yang bisa dinyalakan, dan parameter. Setiap perubahan dicatat di riwayat.</p>
      <div class="grid g2">
        <div class="card"><h3>Versi aplikasi</h3><p class="hint">Isi setelah versi baru masuk produksi.</p>
          <div class="row2"><div class="field"><label>Versi terbaru</label><input id="rv" value="${esc(rel.latest_version)}"></div><div class="field"><label>Build terbaru</label><input id="rb" inputmode="numeric" value="${esc(rel.latest_build ?? '')}" placeholder="mis. 55"></div></div>
          <div class="field"><label>Versi minimum (di bawah ini dipaksa update)</label><input id="rm" value="${esc(rel.minimum_required_version)}"></div>
          <div class="field"><label>Pesan (opsional)</label><input id="rmsg" value="${esc(rel.message ?? '')}"></div>
          <div class="warn">Menaikkan versi minimum memblokir app versi lama. Cek dulu.</div><button class="btn" data-act="rel-save">Simpan</button></div>
        <div class="card"><h3>Fitur</h3><p class="hint">Tabel app_feature_flags. Ketuk untuk menyalakan atau mematikan.</p><div class="tablewrap"><table>${flags.map((f) => `<tr><td><b>${esc(f.key)}</b><br><span class="hint">${when(f.updated_at)}</span></td><td class="n"><span class="switch ${f.enabled ? 'on' : ''}" data-act="flag" data-key="${esc(f.key)}"></span></td></tr>`).join('')}</table></div></div>
        <div class="card"><h3>Parameter</h3><p class="hint">Tabel app_parameters (angka kuota dan harga ada di sini). Catatan pembaruan diubah lewat migrasi.</p>${params.map((p) => `<div class="field"><label>${esc(p.key)}</label><div style="display:flex;gap:8px"><input class="sm-input" data-pkey="${esc(p.key)}" value="${esc(p.value)}"><button class="btn sm" data-act="param-save" data-key="${esc(p.key)}">Simpan</button></div></div>`).join('')}</div>
        <div class="card"><h3>Asumsi estimasi keuntungan</h3><p class="hint">Dipakai di Ringkasan. Samakan dengan harga di Play Console.</p>${sets.map((x) => `<div class="field"><label>${esc(SET_LABEL[x.key] || x.key)}</label><div style="display:flex;gap:8px"><input class="sm-input" inputmode="decimal" data-skey="${esc(x.key)}" value="${esc(x.value)}"><button class="btn sm" data-act="set-save" data-key="${esc(x.key)}">Simpan</button></div></div>`).join('')}</div>
        <div class="card"><h3>Riwayat aksi admin</h3><p class="hint">15 terakhir</p><div class="tablewrap"><table>${audit.map((a) => `<tr><td>${when(a.at)}<br><span class="hint">${esc(a.admin_email)}</span></td><td><b>${esc(a.action)}</b><br><span class="hint mono pm">${esc(JSON.stringify(a.detail))}</span></td></tr>`).join('') || '<tr><td class="hint">Belum ada.</td></tr>'}</table></div></div>
      </div>`;
  }
  async function relSave() {
    const b = $('#rb').value.trim();
    if (!confirm('Simpan versi rilis? Pengguna akan melihat perubahannya.')) return;
    try { await rpc('admin_set_release', { p_latest_version: $('#rv').value.trim(), p_latest_build: b === '' ? null : parseInt(b, 10), p_minimum: $('#rm').value.trim(), p_message: $('#rmsg').value }); toast('Versi disimpan.'); route(); } catch (e) { fail(e); }
  }
  async function flagToggle(el) {
    const on = !el.classList.contains('on');
    try { await rpc('admin_set_flag', { p_key: el.dataset.key, p_enabled: on }); el.classList.toggle('on', on); toast(el.dataset.key + (on ? ' menyala.' : ' mati.')); } catch (e) { fail(e); }
  }
  async function setSave(key) {
    const el = $(`[data-skey="${CSS.escape(key)}"]`);
    try { await rpc('admin_set_setting', { p_key: key, p_value: Number(String(el.value).replace(/[^0-9.]/g, '')) }); toast('Asumsi disimpan.'); } catch (e) { fail(e); }
  }
  async function paramSave(key) {
    const el = $(`[data-pkey="${CSS.escape(key)}"]`);
    if (!confirm('Simpan parameter ' + key + '?')) return;
    try { await rpc('admin_set_parameter', { p_key: key, p_value: el.value }); toast('Parameter disimpan.'); } catch (e) { fail(e); }
  }

  // ------------------------------------------------------------------ events
  document.addEventListener('click', (ev) => {
    const barBtn = ev.target.closest('.chartbox .bar');
    if (barBtn) { pickBar(barBtn); return; }
    const kindBtn = ev.target.closest('#annkind button');
    if (kindBtn) { $$('#annkind button').forEach((b) => b.classList.remove('on')); kindBtn.classList.add('on'); return; }
    if (ev.target.id === 'modal') return closeModal();
    const el = ev.target.closest('[data-act]');
    if (!el) return;
    const act = el.dataset.act;
    if (el.tagName === 'A') ev.preventDefault();
    const go = {
      login, signout: signOut, close: closeModal, reload: route,
      theme: () => applyTheme(THEMES[(THEMES.indexOf(getTheme()) + 1) % 3]),
      'mfa-verify': () => mfaVerify(el.dataset.factor),
      'ann-resolve': () => annResolve(el.dataset.id), 'ann-update': () => annUpdateModal(el.dataset.id), 'ann-update-save': () => annUpdateSave(el.dataset.id),
      'ann-push': () => confirm('Kirim push ke semua user?') && sendPush(el.dataset.id),
      usearch: () => { userQuery = $('#uq').value.trim(); route(); },
      unmask: () => { unmask = !unmask; route(); },
      tier: () => tierModal(el.dataset.email, el.dataset.type), 'tier-save': () => tierSave(el.dataset.email),
      'cost-days': () => { cost.days = +el.dataset.v; route(); }, 'cost-own': () => { cost.hideOwn = !cost.hideOwn; route(); },
      'quota-one': quotaOne, 'quota-all': quotaAllModal, 'quota-all-do': quotaAllDo,
      'ai-tab': () => { aip.tab = el.dataset.v; sgSave(); route(); }, 'ai-metric': () => { aip.metric = el.dataset.v; sgSave(); route(); }, 'ai-usearch': () => { aip.uq = ($('#aiq').value || '').trim(); sgSave(); route(); }, 'ai-pick': () => { aip.account = el.dataset.email; aip.tab = 'user'; aip.uq = ''; sgSave(); route(); }, 'ai-clear': () => { aip.account = ''; sgSave(); route(); }, 'ai-tier': () => { aip.list.tier = el.dataset.v; aip.list.page = 0; sgSave(); route(); }, 'ai-lrange': () => { aip.list.range = el.dataset.v; aip.list.page = 0; sgSave(); route(); }, 'ai-lsearch': () => { aip.list.q = ($('#aiq').value || '').trim(); aip.list.page = 0; sgSave(); route(); }, 'ai-page': () => { aip.list.page = Math.max(0, aip.list.page + Number(el.dataset.d)); sgSave(); route(); }, 'ai-csv': aiCsv, 'rel-save': relSave, 'ledger-add': () => ledgerAdd(el.dataset.kind), 'ledger-del': () => ledgerDel(el.dataset.id), 'sg-type': () => { prefOf(el.dataset.c).type = el.dataset.v; sgSave(); route(); }, 'sg-range': () => { prefOf(el.dataset.c).range = el.dataset.v; sgSave(); route(); }, 'sg-metric': () => { prefOf(el.dataset.c).metric = el.dataset.v; sgSave(); route(); }, 'set-save': () => setSave(el.dataset.key), 'sum-days': () => { sumDays = +el.dataset.v; route(); }, flag: () => flagToggle(el), 'param-save': () => paramSave(el.dataset.key),
    }[act];
    if (go) go();
  });
  document.addEventListener('change', (ev) => {
    if (ev.target.matches('[data-act=cost-fn]')) { cost.fn = ev.target.value; route(); }
    if (ev.target.matches('[data-act=ai-fn]')) { aip.fn = ev.target.value; aip.list.page = 0; sgSave(); route(); }
    if (ev.target.matches('[data-act=ai-sort]')) { aip.list.sort = ev.target.value; aip.list.page = 0; sgSave(); route(); }
    if (ev.target.matches('[data-act=sg-day]')) { prefOf(ev.target.dataset.c || 'series').day = ev.target.value; sgSave(); route(); }
    if (ev.target.matches('[data-act=sg-dow]')) { prefOf(ev.target.dataset.c || 'hour').dow = ev.target.value; sgSave(); route(); }
    if (ev.target.name === 'audience') {
      const push = $('#sendpush'); if (push) { push.disabled = ev.target.value !== 'all'; if (push.disabled) push.checked = false; }
    }
  });
  document.addEventListener('submit', (ev) => { if (ev.target.id === 'annform') { ev.preventDefault(); annSubmit(ev.target); } });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && ev.target.id === 'aiq') { const b = $('[data-act=ai-usearch]') || $('[data-act=ai-lsearch]'); if (b) b.click(); }
    if (ev.key === 'Enter' && ev.target.id === 'uq') { userQuery = ev.target.value.trim(); route(); }
    if (ev.key === 'Enter' && ev.target.id === 'mfacode') { const b = $('[data-act=mfa-verify]'); if (b) b.click(); }
    if (ev.key === 'Escape') closeModal();
  });

  applyTheme(getTheme());
  boot();
})();
