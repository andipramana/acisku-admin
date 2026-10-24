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
    ['pengumuman', '📢', 'Pengumuman', pgPengumuman],
    ['pengguna', '👤', 'Pengguna', pgPengguna],
    ['biaya', '💸', 'Biaya AI', pgBiaya],
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
  function bars(items, fmt) {
    const max = Math.max(1, ...items.map((i) => i.v));
    const n = items.length;
    return `<div class="bars">${items.map((it, i) => `<div class="${i === n - 1 ? 'now' : ''}" style="height:${Math.max(4, (it.v / max) * 100)}%" title="${esc(it.l)}: ${esc(fmt(it.v))}"><b>${i % 3 === (n - 1) % 3 ? esc(fmt(it.v)) : ''}</b></div>`).join('')}</div>
      <div class="axis">${items.map((it, i) => `<span>${i % 2 === (n - 1) % 2 ? esc(it.l) : ''}</span>`).join('')}</div>`;
  }
  const chip = (cls, t) => `<span class="chip ${cls}">${esc(t)}</span>`;
  const tierChip = (t) => (t === 'max' ? chip('bl', 'Max') : t === 'pro' ? chip('gr', 'Pro') : chip('mu', 'Free'));

  // ------------------------------------------------------------------ Ringkasan
  async function pgRingkasan() {
    const [o, su, co] = await Promise.all([rpc('admin_overview'), rpc('admin_signups_per_day', { p_days: 14 }), rpc('admin_ai_cost_per_day', { p_days: 14 })]);
    const y = Number(o.ai_cost_idr_yesterday || 0), t = Number(o.ai_cost_idr_today || 0);
    const delta = y > 0 ? Math.round(((t - y) / y) * 100) : null;
    const rel = o.release || {};
    return `<h1>Ringkasan</h1><p class="sub">Angka utama. Hari dihitung WIB; akun uji tidak ikut biaya AI.</p>
      <div class="grid g4" style="margin-bottom:14px">
        <div class="card kpi"><div class="v">${num(o.signups_total)}</div><div class="l">Pendaftar total</div><div class="d up">+${num(o.signups_today)} hari ini</div></div>
        <div class="card kpi"><div class="v">${num(Number(o.pro) + Number(o.max))}</div><div class="l">Pro / Max aktif</div><div class="d">${num(o.pro)} Pro · ${num(o.max)} Max</div></div>
        <div class="card kpi"><div class="v">${rp(t)}</div><div class="l">Biaya AI hari ini</div><div class="d ${delta != null && delta > 0 ? 'down' : 'up'}">${delta == null ? '—' : (delta > 0 ? '+' : '') + delta + '% dari kemarin'}</div></div>
        <div class="card kpi"><div class="v">${num(o.ai_calls_today)}</div><div class="l">Panggilan AI hari ini</div><div class="d">cache ${o.cache_ratio_today == null ? '—' : Math.round(o.cache_ratio_today * 100) + '%'}</div></div>
      </div>
      <div class="grid g2">
        <div class="card"><h3>Pendaftar per hari</h3><p class="hint">14 hari terakhir</p>${bars(su.map((r) => ({ l: dayLabel(r.day), v: Number(r.n) })), (v) => v)}</div>
        <div class="card"><h3>Biaya AI per hari</h3><p class="hint">Rupiah</p>${bars(co.map((r) => ({ l: dayLabel(r.day), v: Number(r.cost_idr) })), (v) => (v >= 1000 ? (v / 1000).toFixed(1) + 'rb' : Math.round(v)))}</div>
      </div>
      <div class="card" style="margin-top:14px"><h3>Yang sedang aktif</h3><div class="tablewrap"><table>
        <tr><td>Pengumuman berlangsung</td><td>${Number(o.announcements_active) ? chip('red', o.announcements_active + ' aktif') : chip('gr', 'tidak ada')}</td><td class="n"><a href="#pengumuman">Buka</a></td></tr>
        <tr><td>Versi terbaru / minimum</td><td>${chip('gr', (rel.latest_version || '?') + (rel.latest_build ? '+' + rel.latest_build : '') + ' / ' + (rel.minimum_required_version || '?'))}</td><td class="n"><a href="#rilis">Buka</a></td></tr>
        <tr><td>Fitur menyala</td><td>${(o.flags_on || []).map((f) => chip('mu', f)).join(' ')}</td><td class="n"><a href="#rilis">Buka</a></td></tr></table></div></div>`;
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
    const rows = users.map((u) => `<tr><td>${who(u.email)}<br><span class="hint">daftar ${when(u.created_at)} · masuk ${when(u.last_sign_in_at)}</span></td><td>${tierChip(u.subscription_type)}</td><td>${esc(u.tier_source || '—')}</td>
      <td class="n">${u.tier_source === 'play' ? '<span class="hint">dari Play</span>' : `<button class="btn sm sec" data-act="tier" data-email="${esc(u.email)}" data-type="${esc(u.subscription_type)}">Ubah</button>`}</td></tr>`).join('');
    return `<h1>Pengguna</h1><p class="sub">Cari akun dan ubah paketnya (hadiah). Paket yang berasal dari Google Play tidak bisa diubah di sini.</p>
      <div class="card"><div class="row2" style="grid-template-columns:1fr auto auto;align-items:start"><div class="field" style="margin:0"><input id="uq" placeholder="email atau sebagian email" value="${esc(userQuery)}"></div><button class="btn" data-act="usearch">Cari</button><button class="btn sec" data-act="unmask">${unmask ? 'Sembunyikan email' : 'Tampilkan email'}</button></div>
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
    const [perDay, perAcc, exp] = await Promise.all([
      rpc('admin_ai_cost_per_day', { p_days: cost.days, p_function: fn }),
      rpc('admin_ai_cost_per_account', { p_days: cost.days, p_function: fn, p_hide_own: cost.hideOwn }),
      rpc('admin_expensive_calls', { p_min_idr: 20, p_limit: 30 }),
    ]);
    const chips = [[1, 'Hari ini'], [7, '7 hari'], [30, '30 hari'], [90, '90 hari']].map(([d, t]) => `<button data-act="cost-days" data-v="${d}" class="${cost.days === d ? 'on' : ''}">${t}</button>`).join('');
    const total = perDay.reduce((s, r) => s + Number(r.cost_idr), 0), reqs = perDay.reduce((s, r) => s + Number(r.requests), 0);
    return `<h1>Biaya AI</h1><p class="sub">Dari tabel panggilan AI. Akun uji tidak ikut dihitung. Kurs Rp17.900 per USD.</p>
      <div class="tl">${chips}<span style="flex:1"></span>
        <select data-act="cost-fn"><option value="">Semua fitur</option>${['ai-chat', 'receipt-analyze', 'quick-add', 'scan', 'business-sale-parse'].map((f) => `<option ${cost.fn === f ? 'selected' : ''}>${f}</option>`).join('')}</select>
        <button data-act="cost-own" class="${cost.hideOwn ? 'on' : ''}">Sembunyikan akun saya</button><button data-act="unmask" class="${unmask ? 'on' : ''}">Email penuh</button></div>
      <div class="grid g3" style="margin-bottom:14px"><div class="card kpi"><div class="v">${rp(total)}</div><div class="l">Biaya ${cost.days} hari</div></div><div class="card kpi"><div class="v">${num(reqs)}</div><div class="l">Permintaan</div></div><div class="card kpi"><div class="v">${reqs ? rp(total / reqs) : '—'}</div><div class="l">Rata-rata per permintaan</div></div></div>
      <div class="grid g2">
        <div class="card"><h3>Per hari</h3><div class="tablewrap"><table><tr><th>Tanggal</th><th class="n">Permintaan</th><th class="n">USD</th><th class="n">Rupiah</th></tr>${[...perDay].reverse().slice(0, 31).map((r) => `<tr><td>${esc(String(r.day).slice(5))}</td><td class="n">${num(r.requests)}</td><td class="n">${usd(r.cost_usd)}</td><td class="n">${rp(r.cost_idr)}</td></tr>`).join('')}</table></div></div>
        <div class="card"><h3>Per akun</h3><p class="hint">${cost.days === 1 ? 'Hari ini' : cost.days + ' hari terakhir'} (hari ini WIB tidak dipisah)</p><div class="tablewrap"><table><tr><th>Akun</th><th class="n">Panggilan</th><th class="n">Rata-rata USD</th><th class="n">Rupiah</th></tr>${perAcc.slice(0, 25).map((r) => `<tr><td class="mono">${who(r.account_key)}</td><td class="n">${num(r.calls)}</td><td class="n">${usd(r.avg_usd)}</td><td class="n">${rp(r.cost_idr)}</td></tr>`).join('') || '<tr><td colspan="4" class="hint">Kosong.</td></tr>'}</table></div></div>
      </div>
      <div class="card" style="margin-top:14px"><h3>Panggilan mahal</h3><p class="hint">Biaya ≥ Rp20 per panggilan, 30 terbaru</p><div class="tablewrap"><table><tr><th>Waktu</th><th>Akun</th><th>Fungsi</th><th class="n">Cache</th><th class="n">Rupiah</th></tr>${exp.map((r) => `<tr><td>${when(r.created_at)}</td><td class="mono">${who(r.account_key)}</td><td>${esc(r.edge_function)}</td><td class="n">${r.cache_hit_ratio == null ? '—' : Math.round(r.cache_hit_ratio * 100) + '%'}</td><td class="n">${rp(r.cost_idr)}</td></tr>`).join('') || '<tr><td colspan="5" class="hint">Tidak ada.</td></tr>'}</table></div></div>`;
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
    const [rel, flags, params, audit] = await Promise.all([rpc('admin_get_release'), rpc('admin_list_flags'), rpc('admin_list_parameters'), rpc('admin_audit_list', { p_limit: 15 })]);
    return `<h1>Rilis dan pengaturan</h1><p class="sub">Versi aplikasi, fitur yang bisa dinyalakan, dan parameter. Setiap perubahan dicatat di riwayat.</p>
      <div class="grid g2">
        <div class="card"><h3>Versi aplikasi</h3><p class="hint">Isi setelah versi baru masuk produksi.</p>
          <div class="row2"><div class="field"><label>Versi terbaru</label><input id="rv" value="${esc(rel.latest_version)}"></div><div class="field"><label>Build terbaru</label><input id="rb" inputmode="numeric" value="${esc(rel.latest_build ?? '')}" placeholder="mis. 55"></div></div>
          <div class="field"><label>Versi minimum (di bawah ini dipaksa update)</label><input id="rm" value="${esc(rel.minimum_required_version)}"></div>
          <div class="field"><label>Pesan (opsional)</label><input id="rmsg" value="${esc(rel.message ?? '')}"></div>
          <div class="warn">Menaikkan versi minimum memblokir app versi lama. Cek dulu.</div><button class="btn" data-act="rel-save">Simpan</button></div>
        <div class="card"><h3>Fitur</h3><p class="hint">Tabel app_feature_flags. Ketuk untuk menyalakan atau mematikan.</p><div class="tablewrap"><table>${flags.map((f) => `<tr><td><b>${esc(f.key)}</b><br><span class="hint">${when(f.updated_at)}</span></td><td class="n"><span class="switch ${f.enabled ? 'on' : ''}" data-act="flag" data-key="${esc(f.key)}"></span></td></tr>`).join('')}</table></div></div>
        <div class="card"><h3>Parameter</h3><p class="hint">Tabel app_parameters (angka kuota dan harga ada di sini). Catatan pembaruan diubah lewat migrasi.</p>${params.map((p) => `<div class="field"><label>${esc(p.key)}</label><div style="display:flex;gap:8px"><input class="sm-input" data-pkey="${esc(p.key)}" value="${esc(p.value)}"><button class="btn sm" data-act="param-save" data-key="${esc(p.key)}">Simpan</button></div></div>`).join('')}</div>
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
  async function paramSave(key) {
    const el = $(`[data-pkey="${CSS.escape(key)}"]`);
    if (!confirm('Simpan parameter ' + key + '?')) return;
    try { await rpc('admin_set_parameter', { p_key: key, p_value: el.value }); toast('Parameter disimpan.'); } catch (e) { fail(e); }
  }

  // ------------------------------------------------------------------ events
  document.addEventListener('click', (ev) => {
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
      'rel-save': relSave, flag: () => flagToggle(el), 'param-save': () => paramSave(el.dataset.key),
    }[act];
    if (go) go();
  });
  document.addEventListener('change', (ev) => {
    if (ev.target.matches('[data-act=cost-fn]')) { cost.fn = ev.target.value; route(); }
    if (ev.target.name === 'audience') {
      const push = $('#sendpush'); if (push) { push.disabled = ev.target.value !== 'all'; if (push.disabled) push.checked = false; }
    }
  });
  document.addEventListener('submit', (ev) => { if (ev.target.id === 'annform') { ev.preventDefault(); annSubmit(ev.target); } });
  document.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter' && ev.target.id === 'uq') { userQuery = ev.target.value.trim(); route(); }
    if (ev.key === 'Enter' && ev.target.id === 'mfacode') { const b = $('[data-act=mfa-verify]'); if (b) b.click(); }
    if (ev.key === 'Escape') closeModal();
  });

  applyTheme(getTheme());
  boot();
})();
