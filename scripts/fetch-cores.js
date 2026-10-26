'use strict';
/**
 * Скачивает последний релиз sing-box для Windows в папку bin/ (он входит в установщик).
 * Xray в установщик не входит — Hello! скачивает его сам при первом выборе этого ядра.
 * Запуск: npm run fetch-cores   (Xray для разработки: npm run fetch-cores -- xray)
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const BIN = path.join(__dirname, '..', 'bin');
const arm = process.arch === 'arm64';

const CORES = {
  singbox: {
    repo: 'SagerNet/sing-box',
    asset: new RegExp(`windows-${arm ? 'arm64' : 'amd64'}\\.zip$`),
    files: ['sing-box.exe', 'libcronet.dll'],
  },
  xray: {
    repo: 'XTLS/Xray-core',
    asset: new RegExp(`^Xray-windows-${arm ? 'arm64-v8a' : '64'}\\.zip$`),
    files: ['xray.exe'],
  },
};

async function latestAsset(repo, re) {
  const res = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
    headers: { 'User-Agent': 'hello-vpn', Accept: 'application/vnd.github+json' },
  });
  if (!res.ok) throw new Error(`${repo}: GitHub API ответил ${res.status}`);
  const rel = await res.json();
  const asset = rel.assets.find(a => re.test(a.name));
  if (!asset) throw new Error(`${repo}: не найден архив под Windows в релизе ${rel.tag_name}`);
  return { tag: rel.tag_name, name: asset.name, url: asset.browser_download_url };
}

function findFile(dir, name) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const f = findFile(full, name);
      if (f) return f;
    } else if (entry.name.toLowerCase() === name.toLowerCase()) {
      return full;
    }
  }
  return null;
}

async function install(key) {
  const core = CORES[key];
  const a = await latestAsset(core.repo, core.asset);
  console.log(`→ ${core.repo} ${a.tag}: ${a.name}`);
  const res = await fetch(a.url);
  if (!res.ok) throw new Error(`Не удалось скачать ${a.name}: ${res.status}`);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), `core-${key}-`));
  const zip = path.join(tmp, a.name);
  fs.writeFileSync(zip, Buffer.from(await res.arrayBuffer()));
  const out = path.join(tmp, 'x');
  execFileSync('powershell.exe', ['-NoProfile', '-Command',
    `Expand-Archive -LiteralPath '${zip}' -DestinationPath '${out}' -Force`], { stdio: 'inherit' });
  fs.mkdirSync(BIN, { recursive: true });
  for (const f of core.files) {
    const src = findFile(out, f);
    if (src) {
      fs.copyFileSync(src, path.join(BIN, f));
      console.log(`  ✓ ${f}`);
    }
  }
  fs.rmSync(tmp, { recursive: true, force: true });
}

(async () => {
  if (process.platform !== 'win32') {
    console.error('Скрипт рассчитан на Windows (используется Expand-Archive).');
    process.exit(1);
  }
  const which = process.argv.slice(2);
  const keys = which.length ? which : ['singbox'];
  for (const k of keys) {
    if (!CORES[k]) { console.error(`Неизвестное ядро: ${k}`); continue; }
    await install(k);
  }
  console.log(`Готово. Ядра лежат в ${BIN}`);
})().catch(e => { console.error('Ошибка:', e.message); process.exit(1); });
