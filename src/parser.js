'use strict';
/**
 * Парсер share-ссылок (vless/vmess/trojan/ss/hysteria2) и подписок.
 * Всё приводится к единому «профилю», из которого потом собираются
 * конфиги для sing-box и Xray.
 */
const crypto = require('crypto');
const net = require('net');

function b64decode(str) {
  let s = String(str).trim().replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64').toString('utf8');
}

function safeDecode(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}

function stripBrackets(host) {
  return host && host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

function newId() {
  return crypto.randomBytes(6).toString('hex');
}

function normNetwork(t) {
  const n = (t || 'tcp').toLowerCase();
  if (n === 'raw') return 'tcp';
  if (n === 'splithttp') return 'xhttp';
  if (n === 'h2') return 'http';
  return n;
}

function splitList(v) {
  return v ? String(v).split(',').map(s => s.trim()).filter(Boolean) : [];
}

function truthy(v) {
  return v === '1' || v === 'true' || v === true;
}

// vless://uuid@host:port?type=ws&security=reality&...#name
// trojan://password@host:port?security=tls&...#name
function parseVlessTrojan(link, protocol) {
  const u = new URL(link);
  const q = u.searchParams;
  const network = normNetwork(q.get('type'));
  const p = {
    protocol,
    name: safeDecode(u.hash.replace(/^#/, '')) || u.hostname,
    server: stripBrackets(u.hostname),
    port: Number(u.port || 443),
    security: (q.get('security') || (protocol === 'trojan' ? 'tls' : 'none')).toLowerCase(),
    sni: q.get('sni') || q.get('peer') || '',
    fp: q.get('fp') || '',
    alpn: splitList(q.get('alpn')),
    pbk: q.get('pbk') || '',
    sid: q.get('sid') || '',
    spx: q.get('spx') || '',
    allowInsecure: truthy(q.get('allowInsecure')) || truthy(q.get('insecure')),
    network,
    path: q.get('path') || (network === 'xhttp' ? '/' : ''),
    host: q.get('host') || '',
    serviceName: q.get('serviceName') || '',
    mode: q.get('mode') || '',
    headerType: q.get('headerType') || '',
  };
  if (protocol === 'vless') {
    p.uuid = safeDecode(u.username);
    p.flow = q.get('flow') || '';
  } else {
    p.password = safeDecode(u.username);
  }
  return p;
}

// vmess://base64(JSON)
function parseVmess(link) {
  const j = JSON.parse(b64decode(link.slice('vmess://'.length)));
  const network = normNetwork(j.net);
  return {
    protocol: 'vmess',
    name: j.ps || j.add,
    server: j.add,
    port: Number(j.port),
    uuid: j.id,
    alterId: Number(j.aid || 0),
    cipher: j.scy || 'auto',
    security: j.tls === 'tls' ? 'tls' : 'none',
    sni: j.sni || '',
    fp: j.fp || '',
    alpn: splitList(j.alpn),
    allowInsecure: truthy(j.allowInsecure),
    network,
    path: network === 'grpc' ? '' : (j.path || ''),
    host: j.host || '',
    serviceName: network === 'grpc' ? (j.path || '') : '',
    mode: network === 'grpc' ? (j.type || '') : '',
    headerType: network === 'tcp' ? (j.type || '') : '',
  };
}

// ss://base64(method:pass)@host:port#name  |  ss://base64(method:pass@host:port)#name
// ss://method:pass@host:port#name (SIP002 для 2022-шифров)
function parseShadowsocks(link) {
  let body = link.slice('ss://'.length);
  let name = '';
  const hashIdx = body.indexOf('#');
  if (hashIdx >= 0) { name = safeDecode(body.slice(hashIdx + 1)); body = body.slice(0, hashIdx); }
  body = body.split('?')[0].replace(/\/$/, '');

  let userinfo, hostport;
  const at = body.lastIndexOf('@');
  if (at >= 0) {
    userinfo = body.slice(0, at);
    hostport = body.slice(at + 1);
    const dec = safeDecode(userinfo);
    userinfo = dec.includes(':') ? dec : b64decode(userinfo);
  } else {
    const full = b64decode(body);
    const at2 = full.lastIndexOf('@');
    userinfo = full.slice(0, at2);
    hostport = full.slice(at2 + 1);
  }
  const colon = userinfo.indexOf(':');
  const method = userinfo.slice(0, colon);
  const password = userinfo.slice(colon + 1);
  const m = hostport.match(/^\[?([^\]]+?)\]?:(\d+)$/);
  if (!m) throw new Error('Не удалось разобрать адрес Shadowsocks');
  return {
    protocol: 'shadowsocks',
    name: name || m[1],
    server: m[1],
    port: Number(m[2]),
    method,
    password,
    security: 'none',
    network: 'tcp',
  };
}

// hysteria2://auth@host:port[,port-range]/?sni=..&obfs=salamander&obfs-password=..&insecure=1#name
function parseHysteria2(link) {
  let normalized = link.replace(/^hy2:\/\//i, 'hysteria2://');
  let ports = '';
  // Мультипорт (443,20000-30000) не парсится URL — вытаскиваем вручную
  normalized = normalized.replace(/@(\[[^\]]+\]|[^:/?#]+):([\d,\-]+)/, (all, host, prt) => {
    ports = prt;
    return `@${host}:${prt.split(/[,\-]/)[0]}`;
  });
  const u = new URL(normalized);
  const q = u.searchParams;
  const hopPorts = ports.includes(',') || ports.includes('-')
    ? ports.split(',').map(r => r.replace('-', ':'))
    : [];
  return {
    protocol: 'hysteria2',
    name: safeDecode(u.hash.replace(/^#/, '')) || u.hostname,
    server: stripBrackets(u.hostname),
    port: Number(u.port || 443),
    hopPorts,
    password: safeDecode(u.username),
    security: 'tls',
    sni: q.get('sni') || '',
    alpn: splitList(q.get('alpn')),
    allowInsecure: truthy(q.get('insecure')),
    obfs: q.get('obfs') || '',
    obfsPassword: q.get('obfs-password') || '',
    network: 'udp',
  };
}

function parseLink(raw) {
  const link = String(raw).trim();
  const scheme = link.split('://')[0].toLowerCase();
  let p;
  switch (scheme) {
    case 'vless': p = parseVlessTrojan(link, 'vless'); break;
    case 'trojan': p = parseVlessTrojan(link, 'trojan'); break;
    case 'vmess': p = parseVmess(link); break;
    case 'ss': p = parseShadowsocks(link); break;
    case 'hysteria2':
    case 'hy2': p = parseHysteria2(link); break;
    default: throw new Error(`Неподдерживаемый протокол: ${scheme}`);
  }
  if (!p.server || !p.port) throw new Error('В ссылке нет адреса или порта сервера');
  p.id = newId();
  p.raw = link;
  return p;
}

/** Разбирает текст: одна ссылка, несколько ссылок или base64-подписка. */
function parseMany(text) {
  let body = String(text || '').trim();
  if (!body.includes('://')) {
    try { body = b64decode(body); } catch { /* не base64 */ }
  }
  const profiles = [];
  const errors = [];
  for (const line of body.split(/\r?\n/)) {
    const l = line.trim();
    if (!l || !l.includes('://')) continue;
    try { profiles.push(parseLink(l)); } catch (e) { errors.push(`${l.slice(0, 40)}…: ${e.message}`); }
  }
  return { profiles, errors };
}

/** Заголовок subscription-userinfo: upload=..; download=..; total=..; expire=.. */
function parseUserInfo(header) {
  if (!header) return null;
  const info = {};
  for (const part of header.split(';')) {
    const [k, v] = part.split('=').map(s => s && s.trim());
    if (k && v) info[k] = Number(v);
  }
  return info;
}

function isIP(host) {
  return net.isIP(host) !== 0;
}

module.exports = { parseLink, parseMany, parseUserInfo, b64decode, isIP, newId };
