'use strict';
const { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage, shell, Notification } = require('electron');
const { execFile, spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const pkg = require('./package.json');
const { Store } = require('./src/store');
const { parseMany, parseUserInfo, newId } = require('./src/parser');
const { CoreManager, tcpPing } = require('./src/coreManager');
const { listProcesses, iconFor } = require('./src/processes');
const { collectLogs } = require('./src/diagnostics');

const APP_NAME = pkg.displayName || 'Hello!';
const APP_VERSION = pkg.buildNumber
  ? `${pkg.displayVersion}-b${pkg.buildNumber}`
  : (pkg.displayVersion || pkg.version);
const UA_VERSION = pkg.buildNumber ? `${pkg.displayVersion}-b${pkg.buildNumber}` : (pkg.displayVersion || pkg.version);

app.setAppUserModelId(pkg.build && pkg.build.appId ? pkg.build.appId : 'friends.hello.vpn');

if (!app.requestSingleInstanceLock()) {
  app.quit();
  process.exit(0);
}

const BIN_DIR = app.isPackaged
  ? path.join(process.resourcesPath, 'bin')
  : path.join(__dirname, 'bin');
const ICON_PATH = path.join(__dirname, 'renderer', 'icon.png');

let win = null;
let tray = null;
let store = null;
let core = null;
let quitting = false;
const logBuffer = [];

/* ---------------------------- helpers ---------------------------- */

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

function isAdmin() {
  return new Promise(resolve => {
    execFile('net', ['session'], { windowsHide: true }, err => resolve(!err));
  });
}

function relaunchAsAdmin() {
  const q = s => `'${String(s).replace(/'/g, "''")}'`;
  const exe = process.execPath;
  // В режиме разработки electron.exe нужен абсолютный путь к приложению:
  // процесс с повышенными правами стартует в System32, и «.» туда не укажет.
  const appArgs = app.isPackaged ? [] : [`"${app.getAppPath()}"`];
  const cmd = `Start-Process -FilePath ${q(exe)} -Verb RunAs -WorkingDirectory ${q(path.dirname(app.getAppPath()))}` +
    (appArgs.length ? ` -ArgumentList ${appArgs.map(q).join(',')}` : '');
  spawn('powershell.exe', ['-NoProfile', '-Command', cmd], { detached: true, windowsHide: true }).unref();
  quitting = true;
  app.quit();
}

function pushLog(entry) {
  logBuffer.push(entry);
  if (logBuffer.length > 3000) logBuffer.splice(0, logBuffer.length - 3000);
  send('log', entry);
}

function activeProfile() {
  return store.data.profiles.find(p => p.id === store.settings.activeProfileId) || null;
}

function publicState() {
  return {
    app: { name: APP_NAME, version: APP_VERSION },
    settings: store.settings,
    profiles: store.data.profiles,
    subscriptions: store.data.subscriptions,
    core: { state: core.state, auto: !!core.group },
    binDir: BIN_DIR,
    cores: {
      singbox: fs.existsSync(path.join(BIN_DIR, 'sing-box.exe')),
      xray: fs.existsSync(path.join(BIN_DIR, 'xray.exe')),
    },
  };
}

function notify(title, body) {
  try {
    if (Notification.isSupported()) new Notification({ title, body, icon: ICON_PATH, silent: true }).show();
  } catch { /* уведомления недоступны */ }
}

async function fetchSubscription(url) {
  const res = await fetch(url, {
    headers: { 'User-Agent': store.settings.subUserAgent || `Hello/${UA_VERSION}` },
    signal: AbortSignal.timeout(15000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const text = await res.text();
  let name = '';
  const title = res.headers.get('profile-title');
  if (title) {
    name = title.startsWith('base64:')
      ? Buffer.from(title.slice(7), 'base64').toString('utf8')
      : title;
  }
  return { text, name, userInfo: parseUserInfo(res.headers.get('subscription-userinfo')) };
}

async function refreshSubscription(sub) {
  const { text, name, userInfo } = await fetchSubscription(sub.url);
  const { profiles, errors } = parseMany(text);
  if (!profiles.length) throw new Error('В подписке не найдено ни одного сервера');
  const prev = store.data.profiles.filter(p => p.subId === sub.id);
  const prevActive = activeProfile();
  // Заменяем профили этой подписки, сохраняя выбранный сервер и исключения из автовыбора по совпадению ссылки
  store.data.profiles = store.data.profiles.filter(p => p.subId !== sub.id);
  for (const p of profiles) {
    p.subId = sub.id;
    const old = prev.find(o => o.raw === p.raw) || prev.find(o => o.name === p.name);
    if (old && old.noAuto) p.noAuto = true;
    if (prevActive && prevActive.subId === sub.id && old && old.id === prevActive.id) {
      store.settings.activeProfileId = p.id;
    }
  }
  store.data.profiles.push(...profiles);
  if (prevActive && prevActive.subId === sub.id && !activeProfile()) {
    store.settings.activeProfileId = profiles[0].id;
  }
  sub.name = name || sub.name;
  sub.userInfo = userInfo;
  sub.updatedAt = Date.now();
  store.save();
  return { added: profiles.length, errors };
}

function updateTray() {
  if (!tray) return;
  const connected = core.state === 'connected';
  const p = activeProfile();
  tray.setToolTip(connected ? `${APP_NAME} — подключено: ${p ? p.name : ''}` : `${APP_NAME} — отключено`);
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: connected ? 'Отключить' : 'Подключить', click: () => toggleConnection().catch(() => {}) },
    { type: 'separator' },
    { label: 'Открыть', click: () => { win.show(); win.focus(); } },
    { label: 'Собрать логи', click: () => doCollectLogs().catch(e => notify(APP_NAME, e.message)) },
    { type: 'separator' },
    { label: 'Выход', click: () => { quitting = true; app.quit(); } },
  ]));
}

function startCore() {
  return core.start(activeProfile(), store.settings, store.data.profiles);
}

async function toggleConnection() {
  if (core.state === 'connected' || core.state === 'connecting') return core.stop();
  return startCore();
}

async function doCollectLogs() {
  const file = await collectLogs({
    outDir: app.getPath('desktop'),
    appInfo: { name: APP_NAME, version: APP_VERSION, semver: pkg.version },
    store,
    logBuffer,
    history: core.history,
    workDir: core.workDir,
    binDir: BIN_DIR,
    isAdmin: await isAdmin(),
    coreState: core.state,
  });
  shell.showItemInFolder(file);
  pushLog({ source: 'launcher', line: `Логи собраны: ${file}`, ts: Date.now() });
  return file;
}

/* ----------------------------- window ----------------------------- */

function createWindow() {
  win = new BrowserWindow({
    width: 1100,
    height: 760,
    minWidth: 900,
    minHeight: 640,
    backgroundColor: '#0b1022',
    title: APP_NAME,
    icon: ICON_PATH,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
  win.on('close', e => {
    // Закрытие окна сворачивает в трей, VPN продолжает работать
    if (!quitting) { e.preventDefault(); win.hide(); }
  });
  win.webContents.setWindowOpenHandler(({ url }) => { shell.openExternal(url); return { action: 'deny' }; });
}

function createTray() {
  let img = fs.existsSync(ICON_PATH) ? nativeImage.createFromPath(ICON_PATH) : nativeImage.createEmpty();
  if (!img.isEmpty()) img = img.resize({ width: 32, height: 32, quality: 'best' });
  tray = new Tray(img);
  tray.on('click', () => { win.show(); win.focus(); });
  updateTray();
}

/* ------------------------------ IPC ------------------------------ */

function registerIpc() {
  ipcMain.handle('state:get', async () => ({ ...publicState(), admin: await isAdmin() }));
  ipcMain.handle('logs:get', () => logBuffer);
  ipcMain.handle('logs:clear', () => { logBuffer.length = 0; return true; });
  ipcMain.handle('logs:collect', () => doCollectLogs());
  ipcMain.handle('app:relaunchAdmin', () => relaunchAsAdmin());
  ipcMain.handle('app:openBinDir', () => { fs.mkdirSync(BIN_DIR, { recursive: true }); shell.openPath(BIN_DIR); });

  ipcMain.handle('settings:update', async (_e, patch) => store.updateSettings(patch));

  // --- серверы ---
  ipcMain.handle('profiles:import', async (_e, text) => {
    const input = String(text || '').trim();
    if (/^https?:\/\//i.test(input) && !input.includes('\n')) {
      const sub = { id: newId(), name: new URL(input).hostname, url: input };
      store.data.subscriptions.push(sub);
      try {
        const r = await refreshSubscription(sub);
        if (!activeProfile()) store.updateSettings({ activeProfileId: store.data.profiles.find(p => p.subId === sub.id).id });
        return { ...r, state: publicState() };
      } catch (e) {
        store.data.subscriptions = store.data.subscriptions.filter(s => s.id !== sub.id);
        store.save();
        throw e;
      }
    }
    const { profiles, errors } = parseMany(input);
    if (!profiles.length) throw new Error(errors[0] || 'Не найдено ни одной ссылки');
    store.data.profiles.push(...profiles);
    if (!activeProfile()) store.settings.activeProfileId = profiles[0].id;
    store.save();
    return { added: profiles.length, errors, state: publicState() };
  });

  ipcMain.handle('subs:refresh', async (_e, id) => {
    const subs = id ? store.data.subscriptions.filter(s => s.id === id) : store.data.subscriptions;
    const errors = [];
    for (const s of subs) {
      try { await refreshSubscription(s); } catch (e) { errors.push(`${s.name}: ${e.message}`); }
    }
    return { errors, state: publicState() };
  });

  ipcMain.handle('subs:remove', (_e, id) => {
    store.data.subscriptions = store.data.subscriptions.filter(s => s.id !== id);
    store.data.profiles = store.data.profiles.filter(p => p.subId !== id);
    if (!activeProfile()) store.settings.activeProfileId = store.data.profiles[0]?.id || null;
    store.save();
    return publicState();
  });

  ipcMain.handle('profiles:remove', (_e, id) => {
    store.data.profiles = store.data.profiles.filter(p => p.id !== id);
    if (store.settings.activeProfileId === id) store.settings.activeProfileId = store.data.profiles[0]?.id || null;
    store.save();
    return publicState();
  });

  ipcMain.handle('profiles:setAuto', (_e, id, included) => {
    const p = store.data.profiles.find(x => x.id === id);
    if (p) { if (included) delete p.noAuto; else p.noAuto = true; store.save(); }
    return publicState();
  });

  ipcMain.handle('profiles:select', async (_e, id) => {
    store.updateSettings({ activeProfileId: id });
    updateTray();
    if (core.state === 'connected') {
      // Внутри группы автопереключения — мгновенно, без перезапуска TUN
      const switched = await core.selectInGroup(id).catch(() => false);
      if (!switched) await startCore();
    }
    return publicState();
  });

  ipcMain.handle('profiles:ping', async (_e, ids) => {
    const list = store.data.profiles.filter(p => !ids || ids.includes(p.id));
    const results = {};
    await Promise.all(list.map(async p => {
      // Hysteria2 работает по UDP — TCP-пинг для него бессмыслен
      results[p.id] = p.protocol === 'hysteria2' ? -2 : await tcpPing(p.server, p.port);
    }));
    return results;
  });

  // --- приложения / процессы ---
  ipcMain.handle('proc:list', () => listProcesses(app));

  ipcMain.handle('proc:pickExe', async () => {
    const r = await dialog.showOpenDialog(win, {
      title: 'Выберите программу',
      filters: [{ name: 'Программы', extensions: ['exe'] }],
      properties: ['openFile', 'multiSelections'],
    });
    if (r.canceled) return [];
    return Promise.all(r.filePaths.map(async p => ({
      name: path.basename(p), path: p, icon: await iconFor(app, p),
    })));
  });

  ipcMain.handle('apps:set', async (_e, apps) => {
    store.updateSettings({ apps });
    return store.settings;
  });

  ipcMain.handle('apps:icons', async () => {
    const out = {};
    await Promise.all(store.settings.apps.filter(a => a.path).map(async a => { out[a.path] = await iconFor(app, a.path); }));
    return out;
  });

  // --- подключение ---
  ipcMain.handle('vpn:connect', async () => { await startCore(); return core.state; });
  ipcMain.handle('vpn:disconnect', async () => { await core.stop(); return core.state; });
  ipcMain.handle('vpn:restart', async () => {
    if (core.state === 'connected') await startCore();
    return core.state;
  });
}

/* ------------------------------ app ------------------------------ */

app.whenReady().then(() => {
  const appData = app.getPath('appData');
  store = new Store(app.getPath('userData'), [path.join(appData, 'vpn-launcher'), path.join(appData, 'VPN Launcher')]);
  core = new CoreManager(BIN_DIR, path.join(app.getPath('userData'), 'run'));

  core.on('log', pushLog);
  core.on('state', st => { send('vpn:state', st); updateTray(); });
  core.on('switch', entry => {
    // Рабочий сервер становится выбранным — при следующем запуске начнём с него
    if (entry.toId && store.data.profiles.some(p => p.id === entry.toId)) {
      store.updateSettings({ activeProfileId: entry.toId });
    }
    send('vpn:switch', { ...entry, state: publicState() });
    updateTray();
    notify(APP_NAME, `Сервер не отвечал — переключились на «${entry.to}» (${entry.delay} мс)`);
  });
  core.on('allDown', () => {
    send('vpn:allDown');
    notify(APP_NAME, 'Все серверы подписки сейчас недоступны. Продолжаю проверять.');
  });
  core.on('health', h => send('vpn:health', h));

  registerIpc();
  createWindow();
  createTray();
  pushLog({ source: 'launcher', line: `${APP_NAME} ${APP_VERSION} запущен`, ts: Date.now() });

  // Автообновление подписок раз в 6 часов
  setInterval(() => {
    store.data.subscriptions.forEach(s => refreshSubscription(s).catch(() => {}));
  }, 6 * 60 * 60 * 1000);
});

app.on('second-instance', () => { if (win) { win.show(); win.focus(); } });

app.on('before-quit', async e => {
  if (core && Object.keys(core.procs).length) {
    e.preventDefault();
    quitting = true;
    await core.stop();
    app.quit();
  }
});
