'use strict';
/** Быстрая проверка парсера и сборщика конфигов: npm test */
const assert = require('assert');
const { parseLink, parseMany } = require('../src/parser');
const { buildSingBox, buildXray } = require('../src/configBuilder');
const { DEFAULTS } = require('../src/store');

const links = {
  reality: 'vless://11111111-2222-3333-4444-555555555555@1.2.3.4:443?type=tcp&security=reality&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY123&sid=abcd&flow=xtls-rprx-vision#%D0%9D%D0%B8%D0%B4%D0%B5%D1%80%D0%BB%D0%B0%D0%BD%D0%B4%D1%8B',
  vlessWs: 'vless://uuid-ws@cdn.example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D2048&host=cdn.example.com#WS',
  xhttp: 'vless://uuid-x@x.example.com:443?type=xhttp&security=tls&path=%2Fxh&mode=packet-up#XHTTP',
  vmess: 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'VMess gRPC', add: 'vm.example.com', port: '443', id: 'uuid-vm', aid: '0', net: 'grpc', path: 'grpcsvc', tls: 'tls', sni: 'vm.example.com' })).toString('base64'),
  trojan: 'trojan://p%40ss@tr.example.com:8443?sni=tr.example.com#Trojan',
  ss: 'ss://' + Buffer.from('chacha20-ietf-poly1305:secret').toString('base64') + '@5.6.7.8:8388#SS',
  ss2022: 'ss://2022-blake3-aes-128-gcm:a2V5MTIzNDU2Nzg5MDEyMzQ1Ng%3D%3D@9.9.9.9:443#SS2022',
  hy2: 'hysteria2://authpass@hy.example.com:443,20000-30000/?sni=hy.example.com&obfs=salamander&obfs-password=obfspw&insecure=1#HY2',
};

const p = Object.fromEntries(Object.entries(links).map(([k, v]) => [k, parseLink(v)]));

assert.equal(p.reality.name, 'Нидерланды');
assert.equal(p.reality.security, 'reality');
assert.equal(p.reality.flow, 'xtls-rprx-vision');
assert.equal(p.vmess.serviceName, 'grpcsvc');
assert.equal(p.trojan.password, 'p@ss');
assert.equal(p.ss.method, 'chacha20-ietf-poly1305');
assert.equal(p.ss2022.password, 'a2V5MTIzNDU2Nzg5MDEyMzQ1Ng==');
assert.deepEqual(p.hy2.hopPorts, ['443', '20000:30000']);
assert.equal(p.hy2.port, 443);

// подписка в base64
const sub = Buffer.from(Object.values(links).join('\n')).toString('base64');
assert.equal(parseMany(sub).profiles.length, Object.keys(links).length);

const settings = {
  ...DEFAULTS.settings,
  apps: [
    { name: 'chrome.exe', path: 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', matchBy: 'name', enabled: true },
    { name: 'Telegram.exe', path: 'C:\\Users\\me\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe', matchBy: 'path', enabled: true },
    { name: 'off.exe', matchBy: 'name', enabled: false },
  ],
};

// sing-box, режим include
const sbInc = buildSingBox(p.reality, { ...settings, mode: 'include' });
assert.equal(sbInc.route.final, 'direct');
assert.equal(sbInc.outbounds[0].tls.reality.public_key, 'PUBKEY123');
const appRules = sbInc.route.rules.filter(r => r.process_name?.includes('chrome.exe') || r.process_path);
assert.equal(appRules.length, 2);
assert.ok(appRules.every(r => r.outbound === 'proxy'));
assert.ok(!JSON.stringify(sbInc).includes('off.exe'));

// sing-box, режим exclude
const sbExc = buildSingBox(p.reality, { ...settings, mode: 'exclude' });
assert.equal(sbExc.route.final, 'proxy');
assert.ok(sbExc.route.rules.some(r => r.process_name && r.process_name.includes('chrome.exe') && r.outbound === 'direct'));
assert.ok(sbExc.route.rules.some(r => r.process_name && r.process_name.includes('xray.exe') && r.outbound === 'direct'));

// ws early data
const ws = buildSingBox(p.vlessWs, settings).outbounds[0].transport;
assert.equal(ws.path, '/ws');
assert.equal(ws.max_early_data, 2048);

// hysteria2 с прыжками портов
const hy = buildSingBox(p.hy2, settings).outbounds[0];
assert.deepEqual(hy.server_ports, ['443', '20000:30000']);
assert.equal(hy.obfs.type, 'salamander');

// XHTTP — только Xray
assert.throws(() => buildSingBox(p.xhttp, settings), /XHTTP/);
const xr = buildXray(p.xhttp, { ...settings, core: 'xray' });
assert.equal(xr.outbounds[0].streamSettings.network, 'xhttp');
const sbX = buildSingBox(p.xhttp, { ...settings, core: 'xray' });
assert.equal(sbX.outbounds[0].type, 'socks');

// Xray reality / ss / trojan
assert.equal(buildXray(p.reality, settings).outbounds[0].streamSettings.realitySettings.publicKey, 'PUBKEY123');
assert.equal(buildXray(p.ss, settings).outbounds[0].settings.servers[0].port, 8388);
assert.equal(buildXray(p.trojan, settings).outbounds[0].streamSettings.security, 'tls');
assert.throws(() => buildXray(p.hy2, settings), /sing-box/);

// vmess grpc
assert.equal(buildSingBox(p.vmess, settings).outbounds[0].transport.service_name, 'grpcsvc');

// --- TUN: свободный адрес (например, 172.19.0.1/28 занят NekoBox) ---
const { pickTunAddress, ANSI_RE } = require('../src/coreManager');
assert.equal(pickTunAddress({}), '172.19.0.1/30');
assert.equal(pickTunAddress({ neko: [{ family: 'IPv4', address: '172.19.0.1', netmask: '255.255.255.240' }] }), '172.31.233.1/30');
assert.equal(pickTunAddress({
  a: [{ family: 'IPv4', address: '172.19.0.1', netmask: '255.255.255.252' }],
  b: [{ family: 'IPv4', address: '172.31.0.5', netmask: '255.255.0.0' }],
}), '10.254.233.1/30');
assert.equal('\x1b[31mFATAL\x1b[0m[0000] x'.replace(ANSI_RE, ''), 'FATAL[0000] x');

// --- группа автопереключения ---
const { autoGroup, memberTag } = require('../src/configBuilder');
const subA = parseMany(sub).profiles.map(x => ({ ...x, subId: 'S1' }));
const sel = subA.find(x => x.security === 'reality');
subA.find(x => x.protocol === 'trojan').noAuto = true;
const grp = autoGroup(sel, subA);
assert.equal(grp[0].id, sel.id);
assert.ok(!grp.some(x => x.protocol === 'trojan'), 'исключённый сервер не в группе');
assert.ok(!grp.some(x => x.network === 'xhttp'), 'XHTTP не поддерживается sing-box — не в группе');
const sbG = buildSingBox(sel, settings, { group: grp, clashApi: { port: 9999, secret: 's' }, tunAddress: '10.254.233.1/30' });
const selector = sbG.outbounds.find(o => o.type === 'selector');
assert.equal(selector.tag, 'proxy');
assert.equal(selector.default, memberTag(sel));
assert.equal(selector.outbounds.length, grp.length);
assert.equal(sbG.inbounds[0].address[0], '10.254.233.1/30');
assert.equal(sbG.inbounds[0].interface_name, 'Hello');
assert.equal(sbG.experimental.clash_api.external_controller, '127.0.0.1:9999');
assert.ok(!('disable_color' in sbG.log), 'в sing-box нет поля log.disable_color');
assert.ok(sbG.dns.rules.some(r => r.domain && r.domain.includes('hy.example.com')), 'домены всех серверов группы резолвятся напрямую');
// без группы — одиночный outbound «proxy»
assert.equal(buildSingBox(sel, settings, { group: [sel] }).outbounds[0].tag, 'proxy');

// --- диагностика: секреты вырезаны, zip валиден ---
const { redactObject, makeScrubber, collectSecrets, makeZip } = require('../src/diagnostics');
const scrub = makeScrubber(collectSecrets(subA, [{ url: 'https://sub.example.com/abcDEF123secret' }]));
const red = JSON.stringify(redactObject(sbG, scrub));
for (const secret of ['11111111-2222-3333-4444-555555555555', 'PUBKEY123', 'authpass', 'obfspw', 'cdn.example.com', '1.2.3.4']) {
  assert.ok(!red.includes(secret), `секрет просочился: ${secret}`);
}
assert.ok(red.includes('10.254.233.1/30'), 'адрес TUN должен остаться для отладки');
assert.ok(!scrub('sub https://sub.example.com/abcDEF123secret ok').includes('abcDEF123secret'));
assert.ok(!scrub(links.reality).includes('PUBKEY123'));
const zipBuf = makeZip([{ name: 'a.txt', data: 'привет' }, { name: 'dir/b.json', data: '{"x":1}' }]);
require('fs').writeFileSync(require('os').tmpdir() + '/hello-selftest.zip', zipBuf);

console.log('Все проверки пройдены ✓');
if (process.argv.includes('--print')) {
  console.log(JSON.stringify(sbInc, null, 2));
  console.log(JSON.stringify(xr, null, 2));
}
