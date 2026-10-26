'use strict';
/** Простое JSON-хранилище в папке userData. */
const fs = require('fs');
const path = require('path');

const DEFAULTS = {
  settings: {
    core: 'sing-box',          // 'sing-box' | 'xray'
    mode: 'include',           // 'include' — только выбранные через VPN, 'exclude' — всё, кроме выбранных
    apps: [],                  // [{ name, path, matchBy: 'name'|'path', enabled }]
    activeProfileId: null,
    socksPort: 10808,
    dnsRemote: '1.1.1.1',      // DoH через VPN
    dnsDirect: 'local',        // 'local' (системный) или IP
    dnsOthersViaVpn: true,     // в режиме include: DNS остальных приложений тоже через VPN (защита от подмены)
    tunStack: 'mixed',         // 'mixed' | 'system' | 'gvisor'
    strictRoute: true,
    ipv6: false,
    logLevel: 'info',
    autoSwitch: true,          // автопереключение на рабочий сервер подписки (только sing-box)
    checkInterval: 30,         // секунд между проверками соединения
    subUserAgent: 'Hello/0.1a',
  },
  profiles: [],                // профили серверов
  subscriptions: [],           // [{ id, name, url, updatedAt, userInfo }]
};

class Store {
  /**
   * @param {string}   dir        — папка данных
   * @param {string[]} legacyDirs — старые папки (например, от «VPN Launcher»), откуда перенести настройки
   */
  constructor(dir, legacyDirs = []) {
    this.file = path.join(dir, 'launcher.json');
    this.data = structuredClone(DEFAULTS);
    if (!fs.existsSync(this.file)) {
      for (const d of legacyDirs) {
        const old = path.join(d, 'launcher.json');
        if (fs.existsSync(old)) {
          try { fs.mkdirSync(dir, { recursive: true }); fs.copyFileSync(old, this.file); } catch { /* */ }
          break;
        }
      }
    }
    try {
      const saved = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      this.data = {
        ...this.data,
        ...saved,
        settings: { ...DEFAULTS.settings, ...(saved.settings || {}) },
      };
    } catch { /* первый запуск */ }
  }

  save() {
    fs.mkdirSync(path.dirname(this.file), { recursive: true });
    const tmp = this.file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(this.data, null, 2));
    fs.renameSync(tmp, this.file);
  }

  get settings() { return this.data.settings; }

  updateSettings(patch) {
    Object.assign(this.data.settings, patch);
    this.save();
    return this.data.settings;
  }
}

module.exports = { Store, DEFAULTS };
