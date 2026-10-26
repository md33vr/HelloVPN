'use strict';
/** Список запущенных процессов Windows с путями и иконками. */
const { execFile } = require('child_process');
const path = require('path');

const SYSTEM_SKIP = new Set([
  'system', 'idle', 'registry', 'smss', 'csrss', 'wininit', 'services', 'lsass',
  'svchost', 'fontdrvhost', 'dwm', 'winlogon', 'conhost', 'dllhost', 'sihost',
  'ctfmon', 'runtimebroker', 'searchindexer', 'spoolsv', 'wudfhost', 'taskhostw',
  'sing-box', 'xray', 'memory compression',
]);

function listRaw() {
  const ps = 'Get-Process | Where-Object { $_.Path } | ' +
    'Select-Object Name, Id, Path, @{n="Title";e={$_.MainWindowTitle}} | ConvertTo-Json -Compress';
  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', ps],
      { windowsHide: true, maxBuffer: 32 * 1024 * 1024 },
      (err, stdout) => {
        if (err) return reject(err);
        try {
          const parsed = JSON.parse(stdout || '[]');
          resolve(Array.isArray(parsed) ? parsed : [parsed]);
        } catch (e) { reject(e); }
      });
  });
}

const iconCache = new Map();

async function iconFor(app, exePath) {
  if (iconCache.has(exePath)) return iconCache.get(exePath);
  let url = '';
  try {
    const img = await app.getFileIcon(exePath, { size: 'normal' });
    url = img.toDataURL();
  } catch { /* нет иконки */ }
  iconCache.set(exePath, url);
  return url;
}

/**
 * Возвращает уникальные по пути процессы:
 * [{ name: 'chrome.exe', path, title, pids: [], count, icon, hasWindow }]
 */
async function listProcesses(app) {
  const raw = await listRaw();
  const byPath = new Map();
  for (const p of raw) {
    if (!p.Path || SYSTEM_SKIP.has(String(p.Name).toLowerCase())) continue;
    const key = p.Path.toLowerCase();
    let item = byPath.get(key);
    if (!item) {
      item = { name: path.basename(p.Path), path: p.Path, title: '', pids: [], hasWindow: false };
      byPath.set(key, item);
    }
    item.pids.push(p.Id);
    if (p.Title) { item.title = p.Title; item.hasWindow = true; }
  }
  const list = [...byPath.values()];
  await Promise.all(list.map(async it => { it.icon = await iconFor(app, it.path); }));
  // Сначала оконные приложения, потом по имени
  list.sort((a, b) => (b.hasWindow - a.hasWindow) || a.name.localeCompare(b.name));
  return list;
}

module.exports = { listProcesses, iconFor };
