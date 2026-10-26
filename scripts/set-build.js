'use strict';
/**
 * Проставляет версию во всех местах.
 *   node scripts/set-build.js 2          — билд 2 текущей версии (0.2a-b1 → 0.2a-b2)
 *   node scripts/set-build.js 1 0.3a     — новая версия: 0.3a-b1
 *
 * Схема: version.json { displayVersion: "0.2a", buildNumber: 1 }
 *   → в интерфейсе:   «0.2a-b1»
 *   → файлы:          Hello-Setup-0.2a-b1-win-x64.exe, Hello-0.2a-b1-win-x64-portable.zip
 *   → версия файла:   0.2.1 (major.minor.build — растёт с каждым билдом, Windows видит обновление)
 */
const fs = require('fs');
const path = require('path');

const root = path.join(__dirname, '..');
const versionFile = path.join(root, 'version.json');
const confFile = path.join(root, 'src-tauri', 'tauri.conf.json');
const ver = JSON.parse(fs.readFileSync(versionFile, 'utf8'));
const conf = JSON.parse(fs.readFileSync(confFile, 'utf8'));

const build = Number(process.argv[2]);
const display = process.argv[3] || ver.displayVersion;
if (!Number.isInteger(build) || build < 1) {
  console.error('Использование: node scripts/set-build.js <номер билда> [версия, например 0.2a]');
  process.exit(1);
}
const m = /^(\d+)\.(\d+)([ab])?$/.exec(display);
if (!m) {
  console.error(`Не понимаю версию «${display}». Примеры: 0.2a, 0.3b, 1.0`);
  process.exit(1);
}

ver.displayVersion = display;
ver.buildNumber = build;
conf.version = `${m[1]}.${m[2]}.${build}`;

fs.writeFileSync(versionFile, JSON.stringify(ver, null, 2) + '\n');
fs.writeFileSync(confFile, JSON.stringify(conf, null, 2) + '\n');
console.log(`Версия: Hello! ${display}-b${build} (файл ${conf.version})`);
