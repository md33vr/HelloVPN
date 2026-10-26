'use strict';
/**
 * Запуск/остановка ядер sing-box и Xray, логи, статус,
 * и «сторож» автопереключения серверов через Clash API sing-box.
 */
const { spawn, execFile } = require('child_process');
const { EventEmitter } = require('events');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const { buildSingBox, buildXray, autoGroup, memberTag } = require('./configBuilder');

const ANSI_RE = /\x1b\[[0-9;]*[A-Za-z]/g;
const TEST_URL = 'https://www.gstatic.com/generate_204';

/* ------------------------------ сеть ------------------------------ */

function waitPort(port, timeoutMs = 5000) {
  const until = Date.now() + timeoutMs;
  return new Promise((resolve, reject) => {
    const tryOnce = () => {
      const s = net.connect(port, '127.0.0.1');
      s.once('connect', () => { s.destroy(); resolve(); });
      s.once('error', () => {
        s.destroy();
        if (Date.now() > until) reject(new Error(`Порт ${port} так и не открылся`));
        else setTimeout(tryOnce, 150);
      });
    };
    tryOnce();
  });
}

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

const ip2int = ip => ip.split('.').reduce((a, o) => ((a << 8) | Number(o)) >>> 0, 0);

const TUN_CANDIDATES = ['172.19.0.1/30', '172.31.233.1/30', '10.254.233.1/30', '192.168.233.1/30', '172.27.111.1/30'];

/** Выбирает адрес TUN, не пересекающийся ни с одним существующим интерфейсом (например, TUN NekoBox). */
function pickTunAddress(interfaces = os.networkInterfaces()) {
  const used = [];
  for (const list of Object.values(interfaces)) {
    for (const a of list || []) {
      if (a.family !== 'IPv4' && a.family !== 4) continue;
      used.push({ ip: ip2int(a.address), mask: ip2int(a.netmask || '255.255.255.255') });
    }
  }
  for (const cidr of TUN_CANDIDATES) {
    const [ip, bits] = cidr.split('/');
    const mask = bits === '0' ? 0 : (0xffffffff << (32 - Number(bits))) >>> 0;
    const net0 = (ip2int(ip) & mask) >>> 0;
    const clash = used.some(u => {
      const m = (u.mask & mask) >>> 0; // общая (более короткая) маска
      return ((u.ip & m) >>> 0) === ((net0 & m) >>> 0);
    });
    if (!clash) return cidr;
  }
  return TUN_CANDIDATES[TUN_CANDIDATES.length - 1];
}

/* ---------------------------- Clash API ---------------------------- */

class ClashApi {
  constructor(port, secret) {
    this.base = `http://127.0.0.1:${port}`;
    this.secret = secret;
  }

  async req(method, url, body, timeoutMs = 12000) {
    const res = await fetch(this.base + url, {
      method,
      headers: { Authorization: `Bearer ${this.secret}`, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = text; }
    if (!res.ok) {
      const msg = data && data.message ? data.message : `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }

  current(group) {
    return this.req('GET', `/proxies/${encodeURIComponent(group)}`).then(d => d.now);
  }

  select(group, name) {
    return this.req('PUT', `/proxies/${encodeURIComponent(group)}`, { name });
  }

  /** Задержка через конкретный сервер (мс) или -1 при ошибке. */
  async delay(name, timeout = 5000) {
    try {
      const d = await this.req('GET',
        `/proxies/${encodeURIComponent(name)}/delay?timeout=${timeout}&url=${encodeURIComponent(TEST_URL)}`,
        null, timeout + 3000);
      return d && d.delay > 0 ? d.delay : -1;
    } catch { return -1; }
  }
}

/* ------------------------------ менеджер ------------------------------ */

class CoreManager extends EventEmitter {
  /**
   * @param {string} binDir  — папка с sing-box.exe и xray.exe
   * @param {string} workDir — куда писать конфиги и кэш
   */
  constructor(binDir, workDir) {
    super();
    this.binDir = binDir;
    this.workDir = workDir;
    this.procs = {};             // { singbox, xray }
    this.state = 'disconnected'; // disconnected | connecting | connected | stopping
    this.stopping = false;
    this.api = null;
    this.group = null;           // [{ id, name, tag }]
    this.watch = null;           // таймер сторожа
    this.history = [];           // история переключений
    this.lastTun = null;
  }

  bin(name) {
    const p = path.join(this.binDir, name);
    if (!fs.existsSync(p)) {
      throw new Error(`Не найден ${name} в ${this.binDir}. Запустите «npm run fetch-cores» или положите файл вручную.`);
    }
    return p;
  }

  setState(state, extra = {}) {
    this.state = state;
    this.emit('state', { state, ...extra });
  }

  log(source, line) {
    const clean = String(line).replace(ANSI_RE, '').trimEnd();
    if (clean) this.emit('log', { source, line: clean, ts: Date.now() });
  }

  spawnCore(key, exe, args) {
    const child = spawn(exe, args, { cwd: this.workDir, windowsHide: true });
    this.procs[key] = child;
    const pipe = stream => {
      let buf = '';
      stream.on('data', chunk => {
        buf += chunk.toString();
        const lines = buf.split(/\r?\n/);
        buf = lines.pop();
        lines.forEach(l => this.log(key, l));
      });
    };
    pipe(child.stdout);
    pipe(child.stderr);
    child.on('exit', code => {
      delete this.procs[key];
      this.log(key, `процесс завершён (код ${code})`);
      if (!this.stopping && this.state !== 'disconnected') {
        // Одно из ядер упало — гасим всё
        this.stop().then(() => this.setState('disconnected', { error: `${key} неожиданно завершился (код ${code}). Смотрите журнал.` }));
      }
    });
    return child;
  }

  writeConfig(name, obj) {
    fs.mkdirSync(this.workDir, { recursive: true });
    const file = path.join(this.workDir, name);
    fs.writeFileSync(file, JSON.stringify(obj, null, 2));
    return file;
  }

  /** «sing-box check» — понятная ошибка до запуска, если конфиг не подходит версии ядра. */
  checkSingBox(file) {
    return new Promise((resolve, reject) => {
      execFile(this.bin('sing-box.exe'), ['check', '-c', file, '-D', this.workDir],
        { windowsHide: true, timeout: 15000 },
        (err, stdout, stderr) => {
          if (!err) return resolve();
          const msg = String(stderr || stdout || err.message).replace(ANSI_RE, '').trim();
          msg.split(/\r?\n/).forEach(l => this.log('singbox', l));
          reject(new Error(`Конфиг sing-box не прошёл проверку: ${msg.split(/\r?\n/).pop()}`));
        });
    });
  }

  /**
   * @param {object}   profile
   * @param {object}   settings
   * @param {object[]} allProfiles — все профили (для группы автопереключения)
   */
  async start(profile, settings, allProfiles = []) {
    if (this.state !== 'disconnected') await this.stop();
    if (!profile) throw new Error('Не выбран сервер');
    this.stopping = false;
    this.setState('connecting');
    try {
      const auto = settings.autoSwitch !== false && settings.core !== 'xray';
      let members = auto ? autoGroup(profile, allProfiles) : [profile];
      let clashApi = { port: await freePort(), secret: crypto.randomBytes(12).toString('hex') };
      const tunAddress = pickTunAddress();
      this.lastTun = tunAddress;
      this.log('launcher', `TUN: адрес ${tunAddress}` + (members.length > 1 ? `, автопереключение среди ${members.length} серверов` : ''));

      let sbFile = this.writeConfig('sing-box.json', buildSingBox(profile, settings, { group: members, clashApi, tunAddress }));
      try {
        await this.checkSingBox(sbFile);
      } catch (e) {
        // Сборка sing-box без Clash API — подключаемся без автопереключения, а не падаем
        if (!/clash.?api/i.test(e.message)) throw e;
        this.log('launcher', '⚠ Эта сборка sing-box без Clash API — автопереключение отключено для этого подключения');
        members = [profile];
        clashApi = null;
        sbFile = this.writeConfig('sing-box.json', buildSingBox(profile, settings, { tunAddress }));
        await this.checkSingBox(sbFile);
      }

      if (settings.core === 'xray') {
        const xrConfig = buildXray(profile, settings);
        const xrFile = this.writeConfig('xray.json', xrConfig);
        this.spawnCore('xray', this.bin('xray.exe'), ['run', '-c', xrFile]);
        await waitPort(settings.socksPort);
      }

      this.spawnCore('singbox', this.bin('sing-box.exe'), ['run', '-c', sbFile, '-D', this.workDir]);
      if (clashApi) await waitPort(clashApi.port, 8000).catch(() => {});
      await new Promise(r => setTimeout(r, clashApi ? 400 : 1200));
      if (!this.procs.singbox) throw new Error('sing-box не запустился — подробности в журнале');

      this.api = clashApi ? new ClashApi(clashApi.port, clashApi.secret) : null;
      this.group = this.api && members.length > 1 ? members.map(p => ({ id: p.id, name: p.name, tag: memberTag(p) })) : null;
      this.setState('connected', { profileId: profile.id, since: Date.now(), auto: !!this.group });
      if (this.group) this.startWatchdog(settings);
    } catch (e) {
      await this.stop();
      this.setState('disconnected', { error: e.message });
      throw e;
    }
  }

  /* ----------------------- автопереключение ----------------------- */

  startWatchdog(settings) {
    this.stopWatchdog();
    const interval = Math.max(10, Number(settings.checkInterval) || 30) * 1000;
    let fails = 0;
    let busy = false;
    const tick = async () => {
      if (busy || this.state !== 'connected' || !this.api || !this.group) return;
      busy = true;
      try {
        const now = await this.api.current('proxy');
        const ms = await this.api.delay(now);
        if (ms > 0) {
          if (fails) this.log('launcher', `✓ ${this.nameOf(now)} снова отвечает (${ms} мс)`);
          fails = 0;
          this.emit('health', { tag: now, delay: ms });
        } else {
          fails++;
          this.log('launcher', `✗ ${this.nameOf(now)} не ответил на проверку (${fails}/2)`);
          this.emit('health', { tag: now, delay: -1 });
          if (fails >= 2) {
            fails = 0;
            await this.failover(now, 'нет ответа');
          }
        }
      } catch (e) {
        this.log('launcher', `проверка соединения: ${e.message}`);
      } finally {
        busy = false;
      }
    };
    this.watch = setInterval(tick, interval);
    setTimeout(tick, 5000);
  }

  stopWatchdog() {
    if (this.watch) clearInterval(this.watch);
    this.watch = null;
  }

  nameOf(tag) {
    const m = this.group && this.group.find(g => g.tag === tag);
    return m ? m.name : tag;
  }

  /** Меряет все серверы группы и переключается на самый быстрый рабочий, проверяя каждый. */
  async failover(fromTag, reason) {
    this.log('launcher', `⇄ Ищу замену для «${this.nameOf(fromTag)}»: замеряю серверы подписки…`);
    // Меряем не все разом: в подписке могут быть сотни серверов
    const queue = this.group.filter(g => g.tag !== fromTag);
    const results = [];
    const worker = async () => {
      while (queue.length) {
        const g = queue.shift();
        results.push({ ...g, delay: await this.api.delay(g.tag, 4000) });
      }
    };
    await Promise.all(Array.from({ length: Math.min(24, queue.length) }, worker));
    const alive = results.filter(r => r.delay > 0).sort((a, b) => a.delay - b.delay);
    for (const cand of alive) {
      await this.api.select('proxy', cand.tag);
      const check = await this.api.delay('proxy');
      if (check > 0) {
        const entry = { ts: Date.now(), from: this.nameOf(fromTag), to: cand.name, toId: cand.id, delay: check, reason };
        this.history.push(entry);
        if (this.history.length > 100) this.history.shift();
        this.log('launcher', `⇄ Переключено: ${entry.from} → ${entry.to} (${check} мс, причина: ${reason})`);
        this.emit('switch', entry);
        return true;
      }
      this.log('launcher', `✗ ${cand.name} не прошёл проверку после переключения, пробую следующий`);
    }
    // Ничего не работает — возвращаемся на исходный, сторож попробует снова
    await this.api.select('proxy', fromTag).catch(() => {});
    this.log('launcher', '⚠ Все серверы подписки сейчас недоступны — повторю проверку позже');
    this.emit('allDown');
    return false;
  }

  /** Ручной выбор сервера без перезапуска, если он в текущей группе. */
  async selectInGroup(profileId) {
    if (this.state !== 'connected' || !this.group || !this.api) return false;
    const m = this.group.find(g => g.id === profileId);
    if (!m) return false;
    await this.api.select('proxy', m.tag);
    this.log('launcher', `Сервер выбран вручную: ${m.name}`);
    return true;
  }

  async stop() {
    this.stopping = true;
    this.stopWatchdog();
    this.api = null;
    this.group = null;
    const kill = key => new Promise(resolve => {
      const child = this.procs[key];
      if (!child) return resolve();
      const t = setTimeout(resolve, 3000);
      child.once('exit', () => { clearTimeout(t); resolve(); });
      child.kill();
    });
    if (Object.keys(this.procs).length) this.setState('stopping');
    // Сначала sing-box (снимает маршруты TUN), затем Xray
    await kill('singbox');
    await kill('xray');
    this.stopping = false;
    if (this.state !== 'disconnected') this.setState('disconnected');
  }
}

/** TCP-«пинг»: время установки соединения с сервером. */
function tcpPing(host, port, timeoutMs = 3000) {
  return new Promise(resolve => {
    const start = process.hrtime.bigint();
    const s = net.connect({ host, port });
    const done = val => { s.destroy(); resolve(val); };
    s.setTimeout(timeoutMs, () => done(-1));
    s.once('connect', () => done(Number(process.hrtime.bigint() - start) / 1e6 | 0));
    s.once('error', () => done(-1));
  });
}

module.exports = { CoreManager, tcpPing, pickTunAddress, ANSI_RE };
