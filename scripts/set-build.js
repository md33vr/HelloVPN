'use strict';
/**
 * Проставляет версию во всех местах package.json.
 *   node scripts/set-build.js 3          — билд 3 текущей версии (0.1a-b2 → 0.1a-b3)
 *   node scripts/set-build.js 1 0.2a     — новая версия: 0.2a-b1
 *
 * Схема:  displayVersion "0.1a" + buildNumber 2
 *   → в интерфейсе:   «0.1a-b2»
 *   → файлы:          Hello-Setup-0.1a-b2-win-x64.exe, Hello-0.1a-b2-win-x64-portable.zip
 *   → semver:         0.1.0-alpha.2   (буква a = alpha, b = beta, без буквы = релиз)
 *   → версия файла:   0.1.0.2
 */
const fs = require('fs');
const path = require('path');

const file = path.join(__dirname, '..', 'package.json');
const pkg = JSON.parse(fs.readFileSync(file, 'utf8'));

const build = Number(process.argv[2]);
const display = process.argv[3] || pkg.displayVersion;
if (!Number.isInteger(build) || build < 1) {
  console.error('Использование: node scripts/set-build.js <номер билда> [версия, например 0.1a]');
  process.exit(1);
}
const m = /^(\d+)\.(\d+)(?:\.(\d+))?([ab])?$/.exec(display);
if (!m) {
  console.error(`Не понимаю версию «${display}». Примеры: 0.1a, 0.2b, 1.0`);
  process.exit(1);
}
const [, major, minor, patch = '0', stage] = m;
const pre = stage === 'a' ? `-alpha.${build}` : stage === 'b' ? `-beta.${build}` : '';

pkg.displayVersion = display;
pkg.buildNumber = build;
pkg.version = `${major}.${minor}.${patch}${pre}`;
pkg.build.buildVersion = `${major}.${minor}.${patch}.${build}`;
pkg.build.nsis.artifactName = `Hello-Setup-${display}-b${build}-win-x64.exe`;
pkg.build.win.artifactName = `Hello-${display}-b${build}-win-x64-portable.\${ext}`;
// Каждый билд — в свою папку: старые не нужно удалять (и их могут держать открытыми другие программы)
pkg.build.directories.output = `release/${display}-b${build}`;
pkg.build.nsis.uninstallDisplayName = `Hello! ${display}-b${build}`;

fs.writeFileSync(file, JSON.stringify(pkg, null, 2) + '\n');
console.log(`Версия: Hello! ${display}-b${build}  (${pkg.version}; ${pkg.build.nsis.artifactName}, ${pkg.build.win.artifactName.replace('${ext}', 'zip')})`);
