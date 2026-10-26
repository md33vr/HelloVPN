'use strict';
/* global api */

const $ = sel => document.querySelector(sel);
const $$ = sel => [...document.querySelectorAll(sel)];

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let S = null;                 // состояние из main
let vpn = { state: 'disconnected', since: 0, auto: false };
let health = null;            // { delay } последней проверки через туннель
const pings = {};
let appIcons = {};
let procCache = [];
const procSelected = new Set();

/* ----------------------------- утилиты ----------------------------- */

function toast(msg, kind = '', action) {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.innerHTML = `<span>${esc(msg)}</span>`;
  if (action) {
    const b = document.createElement('button');
    b.className = 'btn small';
    b.textContent = action.label;
    b.onclick = () => { action.run(); el.remove(); };
    el.appendChild(b);
  }
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), action ? 9000 : 4500);
}

async function guard(fn) {
  try { return await fn(); } catch (e) { toast(e.message, 'err'); return undefined; }
}

function fmtBytes(n) {
  if (!n && n !== 0) return '';
  const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
  let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

function protoLabel(p) {
  const tr = p.network && !['tcp', 'udp'].includes(p.network) ? `+${p.network}` : '';
  const sec = p.security === 'reality' ? ' reality' : '';
  return `${p.protocol === 'shadowsocks' ? 'ss' : p.protocol}${tr}${sec}`;
}

const STATE_TEXT = {
  disconnected: 'Отключено',
  connecting: 'Подключение…',
  connected: 'Подключено',
  stopping: 'Отключение…',
};

/* ----------------------------- навигация ----------------------------- */

function showTab(name) {
  $$('.nav-item').forEach(b => b.classList.toggle('active', b.dataset.tab === name));
  $$('.tab').forEach(t => t.classList.toggle('active', t.id === `tab-${name}`));
  if (name === 'home') scrollLogs();
}
$$('.nav-item').forEach(b => b.addEventListener('click', () => showTab(b.dataset.tab)));
$$('[data-goto]').forEach(c => c.addEventListener('click', e => {
  if (e.target.closest('.card-switch')) return;
  showTab(c.dataset.goto);
}));

/* ------------------------------ баннеры ------------------------------ */

function renderBanners() {
  const box = $('#banners');
  box.innerHTML = '';
  if (!S.admin) {
    const b = document.createElement('div');
    b.className = 'banner';
    b.innerHTML = '<span>Для TUN-режима нужны права администратора.</span>';
    const btn = document.createElement('button');
    btn.className = 'btn small';
    btn.textContent = 'Перезапустить от администратора';
    btn.onclick = () => api.relaunchAdmin();
    b.appendChild(btn);
    box.appendChild(b);
  }
  const missing = [];
  if (!S.cores.singbox) missing.push('sing-box.exe');
  if (S.settings.core === 'xray' && !S.cores.xray) missing.push('xray.exe');
  if (missing.length) {
    const b = document.createElement('div');
    b.className = 'banner err';
    b.innerHTML = `<span>Не найдены ядра: ${esc(missing.join(', '))}. Переустановите Hello! или положите файлы в папку ядер.</span>`;
    const btn = document.createElement('button');
    btn.className = 'btn small';
    btn.textContent = 'Открыть папку';
    btn.onclick = () => api.openBinDir();
    b.appendChild(btn);
    box.appendChild(b);
  }
}

/* ------------------------------ главная ------------------------------ */

function activeProfile() {
  return S.profiles.find(p => p.id === S.settings.activeProfileId);
}

function renderHome() {
  const st = vpn.state;
  $('#powerBtn').className = `power ${st}`;
  $('#homeStatus').textContent = STATE_TEXT[st];
  const side = $('#sideStatus');
  side.className = `side-status ${st}`;
  side.querySelector('.txt').textContent = STATE_TEXT[st];

  const p = activeProfile();
  $('#homeServer').textContent = p ? p.name : 'не выбран';
  $('#homeServerSub').textContent = p ? `${protoLabel(p)} · ${p.server}:${p.port}` : 'добавьте сервер';

  const apps = S.settings.apps.filter(a => a.enabled !== false);
  $('#homeMode').textContent = S.settings.mode === 'include' ? 'Только выбранные' : 'Всё, кроме выбранных';
  $('#homeApps').textContent = apps.length
    ? apps.slice(0, 4).map(a => a.name).join(', ') + (apps.length > 4 ? ` и ещё ${apps.length - 4}` : '')
    : (S.settings.mode === 'include' ? 'приложения не выбраны — VPN ни на что не влияет' : 'всё через VPN');
  $('#homeCore').textContent = S.settings.core === 'xray' ? 'Xray' : 'sing-box';

  const autoAvailable = S.settings.core !== 'xray';
  const toggle = $('#autoSwitchToggle');
  toggle.checked = S.settings.autoSwitch !== false && autoAvailable;
  toggle.disabled = !autoAvailable;
  $('#autoBadge').hidden = !(st === 'connected' && vpn.auto);

  let hl = S.settings.core === 'xray' ? 'Xray + TUN через sing-box' : 'TUN через sing-box';
  if (st === 'connected' && health) {
    hl = health.delay > 0 ? `отклик через VPN: ${health.delay} мс` : 'нет ответа через VPN — проверяю…';
  }
  $('#homeHealth').textContent = hl;
  $('#sideVersion').textContent = `${S.app.name} ${S.app.version}`;

  // Объявление провайдера подписки активного сервера (заголовок announce)
  const sub = p && p.subId ? S.subscriptions.find(x => x.id === p.subId) : null;
  const ann = $('#homeAnnounce');
  ann.hidden = !(sub && sub.announce);
  ann.textContent = sub && sub.announce ? sub.announce : '';
}

$('#autoSwitchToggle').addEventListener('change', e => guard(async () => {
  S.settings = await api.updateSettings({ autoSwitch: e.target.checked });
  renderAll();
  offerRestart();
}));

setInterval(() => {
  if (vpn.state !== 'connected' || !vpn.since) { $('#homeTimer').textContent = ''; return; }
  const s = Math.floor((Date.now() - vpn.since) / 1000);
  const hh = String(Math.floor(s / 3600)).padStart(2, '0');
  const mm = String(Math.floor(s / 60) % 60).padStart(2, '0');
  const ss = String(s % 60).padStart(2, '0');
  $('#homeTimer').textContent = `${hh}:${mm}:${ss}`;
}, 1000);

$('#powerBtn').addEventListener('click', () => guard(async () => {
  if (vpn.state === 'connected' || vpn.state === 'connecting') return api.disconnect();
  if (!activeProfile()) { showTab('servers'); throw new Error('Сначала добавьте и выберите сервер'); }
  if (S.settings.mode === 'include' && !S.settings.apps.some(a => a.enabled !== false)) {
    toast('Не выбрано ни одного приложения — трафик пойдёт напрямую', '');
  }
  return api.connect();
}));

/* ------------------------------ серверы ------------------------------ */

function pingClass(ms) {
  if (ms === undefined) return '';
  if (ms < 0) return 'bad';
  return ms < 150 ? 'good' : ms < 350 ? 'mid' : 'bad';
}

function serverRow(p) {
  const row = document.createElement('div');
  row.className = `server${p.id === S.settings.activeProfileId ? ' active' : ''}`;
  const ms = pings[p.id];
  const autoChip = p.subId && S.settings.core !== 'xray'
    ? `<button class="chip auto-chip ${p.noAuto ? 'off' : 'on'}" title="${p.noAuto ? 'Не участвует в автопереключении — нажмите, чтобы включить' : 'Участвует в автопереключении — нажмите, чтобы исключить'}">авто</button>`
    : '<span></span>';
  if (p.noAuto) row.classList.add('excluded');
  row.innerHTML = `
    <div class="radio"></div>
    <div style="min-width:0">
      <div class="server-name">${esc(p.name)}</div>
      <div class="server-addr">${esc(p.server)}:${esc(p.port)}</div>
    </div>
    ${autoChip}
    <span class="tag">${esc(protoLabel(p))}</span>
    <span class="ping ${ms === -2 ? '' : pingClass(ms)}">${ms === undefined ? '—' : ms === -2 ? 'UDP' : ms < 0 ? 'таймаут' : `${ms} мс`}</span>
    <button class="icon-btn" title="Удалить">✕</button>`;
  const chip = row.querySelector('.auto-chip');
  if (chip) chip.addEventListener('click', () => guard(async () => {
    S = { ...S, ...(await api.setProfileAuto(p.id, !!p.noAuto)) };
    renderServers();
    offerRestart();
  }));
  row.addEventListener('click', e => {
    if (e.target.closest('.icon-btn') || e.target.closest('.auto-chip')) return;
    guard(async () => { S = { ...S, ...(await api.selectProfile(p.id)) }; renderAll(); });
  });
  row.querySelector('.icon-btn').addEventListener('click', () => guard(async () => {
    S = { ...S, ...(await api.removeProfile(p.id)) };
    renderAll();
  }));
  return row;
}

function renderServers() {
  const box = $('#serverGroups');
  box.innerHTML = '';
  if (!S.profiles.length) {
    box.innerHTML = '<div class="empty">Серверов пока нет. Вставьте ссылку или URL подписки выше.</div>';
    return;
  }
  const groups = S.subscriptions.map(sub => ({ sub, items: S.profiles.filter(p => p.subId === sub.id) }));
  const manual = S.profiles.filter(p => !p.subId);
  if (manual.length) groups.push({ sub: null, items: manual });

  for (const { sub, items } of groups) {
    const g = document.createElement('div');
    g.className = 'group';
    const head = document.createElement('div');
    head.className = 'group-head';
    let meta = `${items.length} серв.`;
    if (sub && sub.userInfo) {
      const used = (sub.userInfo.upload || 0) + (sub.userInfo.download || 0);
      if (sub.userInfo.total) meta += ` · ${fmtBytes(used)} из ${fmtBytes(sub.userInfo.total)}`;
      else if (used) meta += ` · использовано ${fmtBytes(used)}`;
      if (sub.userInfo.expire) meta += ` · до ${new Date(sub.userInfo.expire * 1000).toLocaleDateString('ru-RU')}`;
    }
    head.innerHTML = `<div><div class="group-title">${esc(sub ? sub.name : 'Добавленные вручную')}</div><div class="group-meta">${esc(meta)}</div>`
      + (sub && sub.announce ? `<div class="group-announce">${esc(sub.announce)}</div>` : '') + `</div>`;
    if (sub) {
      const acts = document.createElement('div');
      acts.className = 'actions';
      for (const [kind, label, url] of [['support', 'Поддержка', sub.supportUrl], ['web', 'Кабинет', sub.webPageUrl]]) {
        if (!url) continue;
        const b = document.createElement('button');
        b.className = 'btn small'; b.textContent = label; b.title = url;
        b.onclick = () => guard(() => api.openSubLink(sub.id, kind));
        acts.appendChild(b);
      }
      const r = document.createElement('button');
      r.className = 'btn small'; r.textContent = 'Обновить';
      r.onclick = () => guard(async () => {
        const res = await api.refreshSubs(sub.id);
        S = { ...S, ...res.state };
        res.errors.forEach(e => toast(e, 'err'));
        if (!res.errors.length) toast('Подписка обновлена', 'ok');
        renderAll();
      });
      const d = document.createElement('button');
      d.className = 'btn small'; d.textContent = 'Удалить';
      d.onclick = () => guard(async () => { S = { ...S, ...(await api.removeSub(sub.id)) }; renderAll(); });
      acts.append(r, d);
      head.appendChild(acts);
    }
    g.appendChild(head);
    items.forEach(p => g.appendChild(serverRow(p)));
    box.appendChild(g);
  }
}

$('#importBtn').addEventListener('click', () => guard(async () => {
  const text = $('#importInput').value.trim();
  if (!text) return;
  $('#importBtn').disabled = true;
  try {
    const res = await api.importProfiles(text);
    S = { ...S, ...res.state };
    $('#importInput').value = '';
    toast(`Добавлено серверов: ${res.added}`, 'ok');
    res.errors.slice(0, 3).forEach(e => toast(e, 'err'));
    renderAll();
  } finally { $('#importBtn').disabled = false; }
}));

$('#pingAll').addEventListener('click', () => guard(async () => {
  $('#pingAll').disabled = true;
  try {
    Object.assign(pings, await api.pingProfiles());
    renderServers();
  } finally { $('#pingAll').disabled = false; }
}));

// Обновление всех подписок — круглая кнопка рядом с кнопкой подключения
$('#homeRefresh').addEventListener('click', () => guard(async () => {
  const btn = $('#homeRefresh');
  if (btn.classList.contains('spin')) return;
  if (!S.subscriptions.length) { showTab('servers'); throw new Error('Подписок пока нет — добавьте ссылку во вкладке «Серверы»'); }
  btn.classList.add('spin');
  try {
    const res = await api.refreshSubs();
    S = { ...S, ...res.state };
    res.errors.forEach(e => toast(e, 'err'));
    if (!res.errors.length) toast('Подписки обновлены', 'ok');
    renderAll();
  } finally { btn.classList.remove('spin'); }
}));

/* ---------------------------- приложения ---------------------------- */

async function saveApps(apps) {
  S.settings = await api.setApps(apps);
  renderApps();
  renderHome();
  offerRestart();
}

function renderApps() {
  $$('input[name="mode"]').forEach(r => { r.checked = r.value === S.settings.mode; });
  const box = $('#appList');
  box.innerHTML = '';
  const apps = S.settings.apps;
  if (!apps.length) {
    box.innerHTML = `<div class="empty">Приложения не выбраны.<br>Нажмите «Добавить из запущенных» или «Выбрать .exe».</div>`;
    return;
  }
  apps.forEach((a, idx) => {
    const row = document.createElement('div');
    row.className = `app-row${a.enabled === false ? ' off' : ''}`;
    const icon = a.path && appIcons[a.path];
    row.innerHTML = `
      <div class="app-icon">${icon ? `<img src="${esc(icon)}" alt="">` : '▣'}</div>
      <div style="min-width:0">
        <div class="app-name">${esc(a.name)}</div>
        <div class="app-path" title="${esc(a.path || '')}">${esc(a.path || 'путь не указан')}</div>
      </div>
      <select title="Как определять процесс">
        <option value="name">по имени</option>
        <option value="path" ${a.path ? '' : 'disabled'}>по пути</option>
      </select>
      <label class="switch" title="Включено"><input type="checkbox" ${a.enabled !== false ? 'checked' : ''}><span></span></label>
      <button class="icon-btn" title="Убрать">✕</button>`;
    const sel = row.querySelector('select');
    sel.value = a.matchBy === 'path' ? 'path' : 'name';
    sel.onchange = () => { apps[idx] = { ...a, matchBy: sel.value }; saveApps(apps); };
    row.querySelector('.switch input').onchange = e => { apps[idx] = { ...a, enabled: e.target.checked }; saveApps(apps); };
    row.querySelector('.icon-btn').onclick = () => { apps.splice(idx, 1); saveApps(apps); };
    box.appendChild(row);
  });
}

$$('input[name="mode"]').forEach(r => r.addEventListener('change', () => guard(async () => {
  S.settings = await api.updateSettings({ mode: r.value });
  renderApps(); renderHome(); offerRestart();
})));

function addApps(list) {
  const apps = [...S.settings.apps];
  let added = 0;
  for (const it of list) {
    if (it.icon) appIcons[it.path] = it.icon;
    const exists = apps.some(a => (a.path && it.path && a.path.toLowerCase() === it.path.toLowerCase())
      || a.name.toLowerCase() === it.name.toLowerCase());
    if (exists) continue;
    apps.push({ name: it.name, path: it.path, matchBy: 'name', enabled: true });
    added++;
  }
  if (added) { saveApps(apps); toast(`Добавлено приложений: ${added}`, 'ok'); }
}

$('#pickExe').addEventListener('click', () => guard(async () => addApps(await api.pickExe())));

/* --- модальное окно процессов --- */

function isAdded(p) {
  return S.settings.apps.some(a => a.name.toLowerCase() === p.name.toLowerCase()
    || (a.path && a.path.toLowerCase() === p.path.toLowerCase()));
}

function renderProcList() {
  const q = $('#procSearch').value.trim().toLowerCase();
  const box = $('#procList');
  box.innerHTML = '';
  const list = procCache.filter(p => !q || p.name.toLowerCase().includes(q)
    || p.title.toLowerCase().includes(q) || p.path.toLowerCase().includes(q));
  for (const p of list) {
    const added = isAdded(p);
    const row = document.createElement('label');
    row.className = `proc${added ? ' added' : ''}`;
    row.innerHTML = `
      <input type="checkbox" ${added ? 'checked disabled' : procSelected.has(p.path) ? 'checked' : ''}>
      ${p.icon ? `<img src="${esc(p.icon)}" alt="">` : '<div class="noicon"></div>'}
      <div style="min-width:0">
        <div class="proc-name">${esc(p.name)}${added ? ' <span class="hint">· уже добавлено</span>' : ''}</div>
        <div class="proc-title" title="${esc(p.path)}">${esc(p.title || p.path)}</div>
      </div>
      <span class="proc-pids">${p.pids.length > 1 ? `${p.pids.length} проц.` : `PID ${p.pids[0]}`}</span>`;
    if (!added) {
      row.querySelector('input').onchange = e => {
        if (e.target.checked) procSelected.add(p.path); else procSelected.delete(p.path);
        $('#procCount').textContent = procSelected.size ? `Выбрано: ${procSelected.size}` : '';
      };
    }
    box.appendChild(row);
  }
  if (!list.length) box.innerHTML = '<div class="empty">Ничего не найдено</div>';
}

async function loadProcs() {
  $('#procList').innerHTML = '<div class="empty">Загрузка списка процессов…</div>';
  procCache = await api.listProcesses();
  renderProcList();
}

$('#openProcPicker').addEventListener('click', () => guard(async () => {
  procSelected.clear();
  $('#procCount').textContent = '';
  $('#procSearch').value = '';
  $('#procModal').hidden = false;
  $('#procSearch').focus();
  await loadProcs();
}));
$('#procClose').addEventListener('click', () => { $('#procModal').hidden = true; });
$('#procModal').addEventListener('click', e => { if (e.target.id === 'procModal') $('#procModal').hidden = true; });
$('#procSearch').addEventListener('input', renderProcList);
$('#procRefresh').addEventListener('click', () => guard(loadProcs));
$('#procAdd').addEventListener('click', () => {
  addApps(procCache.filter(p => procSelected.has(p.path)));
  $('#procModal').hidden = true;
});
document.addEventListener('keydown', e => { if (e.key === 'Escape') $('#procModal').hidden = true; });

/* ----------------------------- настройки ----------------------------- */

function renderSettings() {
  $$('#coreSeg button').forEach(b => b.classList.toggle('on', b.dataset.core === S.settings.core));
  $('#coreHint').textContent = S.settings.core === 'xray'
    ? 'Xray обрабатывает протокол (нужен для XHTTP; скачается при первом подключении), sing-box — TUN и выбор процессов.'
    : 'sing-box делает всё сам: TUN, выбор процессов и протокол (Hysteria2 поддерживается).';
  $$('[data-setting]').forEach(el => {
    const v = S.settings[el.dataset.setting];
    if (el.type === 'checkbox') el.checked = !!v; else el.value = v ?? '';
  });
}

$$('#coreSeg button').forEach(b => b.addEventListener('click', () => guard(async () => {
  S.settings = await api.updateSettings({ core: b.dataset.core });
  renderAll(); offerRestart();
})));

$$('[data-setting]').forEach(el => el.addEventListener('change', () => guard(async () => {
  const key = el.dataset.setting;
  let value = el.type === 'checkbox' ? el.checked : el.value.trim();
  if (el.type === 'number') value = Number(value) || S.settings[key];
  S.settings = await api.updateSettings({ [key]: value });
  renderAll(); offerRestart();
})));

$('#openBin').addEventListener('click', () => api.openBinDir());

let restartToastShown = 0;
function offerRestart() {
  if (vpn.state !== 'connected' || Date.now() - restartToastShown < 3000) return;
  restartToastShown = Date.now();
  toast('Изменения применятся после переподключения', '', {
    label: 'Переподключить',
    run: () => guard(() => api.restart()),
  });
}

/* ------------------------------- журнал ------------------------------- */

const logLines = [];
let logFilter = '';
let lastErrorTs = 0;

const isErr = e => /\b(error|fatal|panic)\b|ERROR|FATAL|✗|⚠|неожиданно|не прошёл|не удалось/i.test(e.line);
const isWarn = e => /\bwarn(ing)?\b/i.test(e.line);
const isSwitch = e => /⇄|✓/.test(e.line);

function srcLabel(s) {
  return s === 'singbox' ? 'sing-box' : s === 'xray' ? 'xray' : s === 'launcher' ? 'hello' : s;
}

// sing-box пишет своё время и уровень в начале строки — оставляем только суть
function tidy(line) {
  return line
    .replace(/^[+-]\d{4}\s+\d{4}-\d\d-\d\d\s+\d\d:\d\d:\d\d\s+/, '')
    .replace(/^\d{4}\/\d\d\/\d\d\s+\d\d:\d\d:\d\d(\.\d+)?\s+/, '');
}

function passes(e) {
  if (!logFilter) return true;
  if (logFilter === 'errors') return isErr(e);
  return e.source === logFilter;
}

function logHtml(e) {
  const t = new Date(e.ts).toLocaleTimeString('ru-RU');
  const cls = isErr(e) ? 'err' : isWarn(e) ? 'warn' : isSwitch(e) ? 'sw' : '';
  return `<div class="log-line ${cls}"><span class="t">${t}</span><span class="s ${esc(e.source)}">${esc(srcLabel(e.source))}</span><span class="m">${esc(tidy(e.line))}</span></div>`;
}

function atBottom() {
  const v = $('#logView');
  return v.scrollHeight - v.scrollTop - v.clientHeight < 40;
}
function scrollLogs() {
  const v = $('#logView');
  v.scrollTop = v.scrollHeight;
  $('#logJump').hidden = true;
}

function renderLogs() {
  const list = logLines.filter(passes);
  $('#logView').innerHTML = list.length
    ? list.map(logHtml).join('')
    : `<div class="log-empty">${logFilter === 'errors' ? 'Ошибок нет 🌊' : 'Пока тихо. Здесь появятся сообщения ядер.'}</div>`;
  scrollLogs();
  renderLogDot();
}

function renderLogDot() {
  const dot = $('#logDot');
  dot.className = 'log-dot' + (Date.now() - lastErrorTs < 5 * 60 * 1000 ? ' err' : vpn.state === 'connected' ? '' : ' idle');
}

function appendLog(e) {
  logLines.push(e);
  if (logLines.length > 3000) logLines.shift();
  if (isErr(e)) lastErrorTs = e.ts;
  renderLogDot();
  if (!passes(e)) return;
  const v = $('#logView');
  const stick = atBottom();
  const empty = v.querySelector('.log-empty');
  if (empty) empty.remove();
  v.insertAdjacentHTML('beforeend', logHtml(e));
  while (v.childElementCount > 1500) v.firstElementChild.remove();
  if (stick) scrollLogs(); else $('#logJump').hidden = false;
}

$('#logView').addEventListener('scroll', () => { if (atBottom()) $('#logJump').hidden = true; });
$('#logJump').addEventListener('click', scrollLogs);

$$('#logChips .chip').forEach(c => c.addEventListener('click', () => {
  logFilter = c.dataset.filter;
  $$('#logChips .chip').forEach(x => x.classList.toggle('on', x === c));
  renderLogs();
}));

$('#logClear').addEventListener('click', () => guard(async () => {
  await api.clearLogs();
  logLines.length = 0;
  lastErrorTs = 0;
  renderLogs();
}));

$('#logCopy').addEventListener('click', () => guard(async () => {
  const text = logLines.filter(passes)
    .map(e => `[${new Date(e.ts).toLocaleTimeString('ru-RU')} ${srcLabel(e.source)}] ${tidy(e.line)}`).join('\n');
  await navigator.clipboard.writeText(text);
  toast('Журнал скопирован', 'ok');
}));

$('#logExpand').addEventListener('click', () => {
  const panel = $('#logPanel');
  const on = !panel.classList.contains('expanded');
  panel.classList.toggle('expanded', on);
  $('#logExpand').textContent = on ? '⤡' : '⤢';
  $('#logExpand').title = on ? 'Свернуть' : 'Развернуть';
  scrollLogs();
});

async function collectLogs(btn) {
  btn.disabled = true;
  const label = btn.textContent;
  btn.textContent = 'Собираю…';
  try {
    const file = await api.collectLogs();
    toast(`Архив сохранён на рабочий стол: ${file.split(/[\\/]/).pop()}`, 'ok');
  } catch (e) {
    toast(`Не удалось собрать логи: ${e.message}`, 'err');
  } finally {
    btn.disabled = false;
    btn.textContent = label;
  }
}
$('#logCollect').addEventListener('click', e => collectLogs(e.currentTarget));
$('#collectLogs2').addEventListener('click', e => collectLogs(e.currentTarget));

/* ------------------------------- старт ------------------------------- */

function renderAll() {
  renderBanners();
  renderHome();
  renderServers();
  renderApps();
  renderSettings();
}

api.onLog(appendLog);
api.onState(st => {
  vpn = { ...vpn, ...st };
  if (st.state !== 'connected') { vpn.since = 0; vpn.auto = false; health = null; }
  if (st.error) toast(st.error, 'err');
  renderHome();
  renderLogDot();
});
api.onSwitch(entry => {
  if (entry.state) S = { ...S, ...entry.state };
  toast(`Сервер не отвечал — переключились на «${entry.to}» (${entry.delay} мс)`, 'ok');
  renderAll();
});
api.onAllDown(() => toast('Все серверы подписки сейчас недоступны. Продолжаю проверять.', 'err'));
api.onHealth(h => { health = h; renderHome(); });

document.addEventListener('keydown', e => {
  if (e.key === 'Escape' && $('#logPanel').classList.contains('expanded')) $('#logExpand').click();
});

(async () => {
  S = await api.getState();
  vpn.state = S.core.state;
  vpn.auto = S.core.auto;
  appIcons = await api.appIcons().catch(() => ({}));
  (await api.getLogs()).forEach(e => { logLines.push(e); if (isErr(e)) lastErrorTs = e.ts; });
  renderAll();
  renderLogs();
})();
