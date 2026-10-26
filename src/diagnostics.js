'use strict';
/**
 * «Собрать логи»: архив для отладки, из которого вырезаны все секреты
 * (UUID, пароли, ключи, адреса серверов, ссылки подписок).
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const { execFile } = require('child_process');

/* ------------------------------ zip ------------------------------ */

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(buf) {
  if (typeof zlib.crc32 === 'function') return zlib.crc32(buf) >>> 0;
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function dosTime(d) {
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time, date };
}

/** Минимальный ZIP (deflate) из списка { name, data }. Имена — UTF-8. */
function makeZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  const { time, date } = dosTime(new Date());
  for (const e of entries) {
    const name = Buffer.from(e.name, 'utf8');
    const raw = Buffer.isBuffer(e.data) ? e.data : Buffer.from(String(e.data), 'utf8');
    const comp = zlib.deflateRawSync(raw, { level: 9 });
    const crc = crc32(raw);

    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4);
    lh.writeUInt16LE(0x0800, 6); // UTF-8
    lh.writeUInt16LE(8, 8);      // deflate
    lh.writeUInt16LE(time, 10);
    lh.writeUInt16LE(date, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(comp.length, 18);
    lh.writeUInt32LE(raw.length, 22);
    lh.writeUInt16LE(name.length, 26);
    lh.writeUInt16LE(0, 28);
    locals.push(lh, name, comp);

    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt16LE(8, 10);
    ch.writeUInt16LE(time, 12);
    ch.writeUInt16LE(date, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(comp.length, 20);
    ch.writeUInt32LE(raw.length, 24);
    ch.writeUInt16LE(name.length, 28);
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, name);
    offset += lh.length + name.length + comp.length;
  }
  const cdSize = centrals.reduce((a, b) => a + b.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(cdSize, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, ...centrals, end]);
}

/* ---------------------------- редактура ---------------------------- */

const SECRET_KEYS = new Set([
  'uuid', 'id', 'password', 'pass', 'public_key', 'publickey', 'pbk', 'short_id', 'shortid', 'sid',
  'private_key', 'secret', 'auth', 'auth_str', 'obfs-password', 'obfspassword', 'obfsPassword',
  'raw', 'url', 'server_ports', 'hopPorts', 'external_controller', 'users',
]);
// Адреса серверов (поля server/address) вычищаются через makeScrubber по списку известных серверов,
// чтобы не потерять полезное для отладки (адрес TUN, DNS 1.1.1.1, 127.0.0.1).

const UUID_RE = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const LINK_RE = /\b(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2|tuic):\/\/\S+/gi;
const URL_RE = /\bhttps?:\/\/[^\s"']+/gi;

/** Строит функцию, которая вычищает строку от известных секретов. */
function makeScrubber(knownSecrets) {
  const list = [...new Set(knownSecrets.filter(s => s && String(s).length >= 4).map(String))]
    .sort((a, b) => b.length - a.length);
  return text => {
    let t = String(text);
    for (const s of list) t = t.split(s).join('***');
    return t.replace(LINK_RE, '<ссылка ***>').replace(UUID_RE, '***');
  };
}

/** Глубокая копия объекта с замаскированными секретными полями. */
function redactObject(obj, scrub) {
  if (Array.isArray(obj)) return obj.map(v => redactObject(v, scrub));
  if (obj && typeof obj === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(obj)) {
      if (SECRET_KEYS.has(k) && v !== '' && v != null && typeof v !== 'boolean') {
        out[k] = '***';
      } else {
        out[k] = redactObject(v, scrub);
      }
    }
    return out;
  }
  return typeof obj === 'string' ? scrub(obj) : obj;
}

function collectSecrets(profiles, subscriptions) {
  const s = [];
  for (const p of profiles || []) {
    s.push(p.uuid, p.password, p.pbk, p.sid, p.obfsPassword, p.raw, p.server);
  }
  for (const sub of subscriptions || []) {
    s.push(sub.url);
    try { const u = new URL(sub.url); s.push(u.pathname.length > 4 ? u.pathname : null, u.search); } catch { /* */ }
  }
  return s.filter(Boolean);
}

/* ------------------------------ сборка ------------------------------ */

function run(cmd, args) {
  return new Promise(resolve => {
    execFile(cmd, args, { windowsHide: true, timeout: 10000, maxBuffer: 4 * 1024 * 1024 },
      (err, stdout, stderr) => resolve(String(stdout || stderr || (err && err.message) || '').trim()));
  });
}

function readIf(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch { return null; }
}

/**
 * @returns {Promise<string>} путь к созданному архиву
 */
async function collectLogs({ outDir, appInfo, store, logBuffer, history, workDir, binDir, isAdmin, coreState }) {
  const { profiles, subscriptions, settings } = store.data;
  const scrub = makeScrubber(collectSecrets(profiles, subscriptions));
  const files = [];

  // 1. Журнал
  const logText = logBuffer.map(e =>
    `[${new Date(e.ts).toISOString()} ${e.source}] ${e.line}`).join('\n');
  files.push({ name: 'journal.log', data: scrub(logText) });

  // 2. Сгенерированные конфиги
  for (const f of ['sing-box.json', 'xray.json']) {
    const raw = readIf(path.join(workDir, f));
    if (!raw) continue;
    try { files.push({ name: `configs/${f}`, data: JSON.stringify(redactObject(JSON.parse(raw), scrub), null, 2) }); }
    catch { files.push({ name: `configs/${f}`, data: scrub(raw) }); }
  }

  // 3. Настройки и серверы (без реквизитов)
  const safeSettings = { ...settings, subUserAgent: settings.subUserAgent };
  files.push({ name: 'settings.json', data: JSON.stringify(redactObject(safeSettings, scrub), null, 2) });
  files.push({
    name: 'servers.json',
    data: JSON.stringify((profiles || []).map(p => ({
      name: scrub(p.name), protocol: p.protocol, network: p.network, security: p.security,
      port: p.port, flow: p.flow || undefined, fp: p.fp || undefined, alpn: p.alpn,
      fromSubscription: !!p.subId, excludedFromAuto: !!p.noAuto,
      active: p.id === settings.activeProfileId,
    })), null, 2),
  });
  files.push({
    name: 'subscriptions.json',
    data: JSON.stringify((subscriptions || []).map(s => ({
      name: scrub(s.name), servers: (profiles || []).filter(p => p.subId === s.id).length,
      updatedAt: s.updatedAt ? new Date(s.updatedAt).toISOString() : null, userInfo: s.userInfo || null,
    })), null, 2),
  });

  // 4. История автопереключений
  files.push({ name: 'autoswitch-history.json', data: scrub(JSON.stringify(history || [], null, 2)) });

  // 5. Система
  const ifaces = Object.entries(os.networkInterfaces()).map(([n, list]) =>
    `${n}: ${(list || []).map(a => `${a.address}/${a.cidr ? a.cidr.split('/')[1] : '?'}`).join(', ')}`).join('\n');
  const sbVer = fs.existsSync(path.join(binDir, 'sing-box.exe')) ? await run(path.join(binDir, 'sing-box.exe'), ['version']) : 'нет';
  const xrVer = fs.existsSync(path.join(binDir, 'xray.exe')) ? await run(path.join(binDir, 'xray.exe'), ['version']) : 'нет';
  const routes = process.platform === 'win32' ? await run('route', ['print', '-4']) : '';
  const system = [
    `Приложение: ${appInfo.name} ${appInfo.version} (${appInfo.semver})`,
    `Electron ${process.versions.electron}, Node ${process.versions.node}, Chromium ${process.versions.chrome}`,
    `ОС: ${os.type()} ${os.release()} ${os.arch()} (${os.version ? os.version() : ''})`,
    `Права администратора: ${isAdmin ? 'да' : 'нет'}`,
    `Состояние VPN: ${coreState}`,
    `Собрано: ${new Date().toString()}`,
    '',
    '== sing-box version ==', sbVer,
    '',
    '== xray version ==', xrVer,
    '',
    '== Сетевые интерфейсы ==', ifaces,
    '',
    '== Таблица маршрутов IPv4 ==', routes,
  ].join('\n');
  files.push({ name: 'system.txt', data: scrub(system) });

  files.push({
    name: 'README.txt',
    data: 'Архив диагностики Hello!.\r\nUUID, пароли, ключи, адреса серверов и ссылки подписок заменены на ***.\r\n' +
      'Его можно спокойно отправить для разбора проблемы.\r\n',
  });

  const stamp = new Date();
  const pad = n => String(n).padStart(2, '0');
  const name = `Hello-logs-${stamp.getFullYear()}-${pad(stamp.getMonth() + 1)}-${pad(stamp.getDate())}_` +
    `${pad(stamp.getHours())}-${pad(stamp.getMinutes())}-${pad(stamp.getSeconds())}.zip`;
  fs.mkdirSync(outDir, { recursive: true });
  const out = path.join(outDir, name);
  fs.writeFileSync(out, makeZip(files));
  return out;
}

module.exports = { collectLogs, makeZip, redactObject, makeScrubber, collectSecrets };
