'use strict';
/**
 * Сборка конфигов.
 *
 * Архитектура:
 *  - sing-box ВСЕГДА поднимает TUN и делает маршрутизацию по процессам
 *    (process_name / process_path) — это самый надёжный способ на Windows.
 *  - Ядро «sing-box»: прокси-outbound собирается прямо в sing-box.
 *  - Ядро «Xray»: Xray слушает локальный SOCKS5, а sing-box отправляет
 *    в него трафик выбранных процессов (outbound type=socks).
 */
const { isIP } = require('./parser');

const CORE_EXE = ['sing-box.exe', 'xray.exe'];

/* ----------------------------- sing-box ----------------------------- */

function sbTls(p) {
  if (!p.security || p.security === 'none') return undefined;
  const tls = { enabled: true };
  const sni = p.sni || (isIP(p.server) ? '' : p.server);
  if (sni) tls.server_name = sni;
  if (p.allowInsecure) tls.insecure = true;
  if (p.alpn && p.alpn.length) tls.alpn = p.alpn;
  const fp = p.fp || (p.security === 'reality' ? 'chrome' : '');
  if (fp) tls.utls = { enabled: true, fingerprint: fp };
  if (p.security === 'reality') {
    tls.reality = { enabled: true, public_key: p.pbk, short_id: p.sid || '' };
  }
  return tls;
}

function sbTransport(p) {
  switch (p.network) {
    case 'tcp':
    case 'udp':
    case undefined:
      return undefined;
    case 'ws': {
      const t = { type: 'ws' };
      let path = p.path || '/';
      // ?ed=2048 в пути — early data через Sec-WebSocket-Protocol
      const m = path.match(/[?&]ed=(\d+)/);
      if (m) {
        t.max_early_data = Number(m[1]);
        t.early_data_header_name = 'Sec-WebSocket-Protocol';
        path = path.replace(/[?&]ed=\d+/, '').replace(/\?$/, '') || '/';
      }
      t.path = path;
      if (p.host) t.headers = { Host: p.host };
      return t;
    }
    case 'grpc':
      return { type: 'grpc', service_name: p.serviceName || '' };
    case 'http':
      return { type: 'http', host: p.host ? [p.host] : undefined, path: p.path || '/' };
    case 'httpupgrade':
      return { type: 'httpupgrade', host: p.host || undefined, path: p.path || '/' };
    case 'xhttp':
      throw new Error('Транспорт XHTTP поддерживает только Xray — переключите ядро в настройках.');
    default:
      throw new Error(`Транспорт «${p.network}» не поддерживается sing-box.`);
  }
}

function sbProxyOutbound(p, tag = 'proxy') {
  const base = { tag, server: p.server, server_port: p.port };
  switch (p.protocol) {
    case 'vless': {
      const o = { type: 'vless', ...base, uuid: p.uuid, packet_encoding: 'xudp' };
      if (p.flow && p.network === 'tcp') o.flow = p.flow;
      o.tls = sbTls(p);
      o.transport = sbTransport(p);
      return o;
    }
    case 'vmess':
      return {
        type: 'vmess', ...base, uuid: p.uuid, security: p.cipher || 'auto',
        alter_id: p.alterId || 0, tls: sbTls(p), transport: sbTransport(p),
      };
    case 'trojan':
      return { type: 'trojan', ...base, password: p.password, tls: sbTls(p), transport: sbTransport(p) };
    case 'shadowsocks':
      return { type: 'shadowsocks', ...base, method: p.method, password: p.password };
    case 'hysteria2': {
      const o = { type: 'hysteria2', ...base, password: p.password, tls: sbTls(p) || { enabled: true } };
      if (!o.tls.alpn) o.tls.alpn = ['h3'];
      if (p.hopPorts && p.hopPorts.length) {
        delete o.server_port;
        o.server_ports = p.hopPorts;
      }
      if (p.obfs) o.obfs = { type: p.obfs, password: p.obfsPassword };
      return o;
    }
    default:
      throw new Error(`Протокол ${p.protocol} не поддерживается sing-box`);
  }
}

/** Собирает правило по выбранным приложениям (отдельно по имени и по пути). */
function appMatchers(apps) {
  const enabled = (apps || []).filter(a => a.enabled !== false);
  const byName = [...new Set(enabled.filter(a => a.matchBy !== 'path').map(a => a.name))];
  const byPath = [...new Set(enabled.filter(a => a.matchBy === 'path' && a.path).map(a => a.path))];
  const out = [];
  if (byName.length) out.push({ process_name: byName });
  if (byPath.length) out.push({ process_path: byPath });
  return out;
}

function dnsDirectServer(settings) {
  const v = (settings.dnsDirect || 'local').trim();
  if (v === 'local') return { type: 'local', tag: 'dns-direct' };
  return { type: 'udp', tag: 'dns-direct', server: v };
}

/** Тег outbound'а сервера в группе автопереключения. */
const memberTag = p => `srv-${p.id}`;

/**
 * Собирает список серверов для группы автопереключения: выбранный — первым,
 * затем остальные из той же подписки, кроме исключённых и несовместимых с sing-box.
 */
function autoGroup(profile, all) {
  const members = [profile];
  for (const p of all || []) {
    if (p.id === profile.id || p.noAuto || !profile.subId || p.subId !== profile.subId) continue;
    try { sbProxyOutbound(p); members.push(p); } catch { /* например, XHTTP */ }
  }
  return members;
}

/**
 * @param {object} profile  — профиль сервера (из parser)
 * @param {object} settings — настройки клиента
 * @param {object} [opts]
 * @param {object[]} [opts.group]    — серверы для автопереключения (см. autoGroup)
 * @param {object}   [opts.clashApi] — { port, secret } для управления и проверок
 * @param {string}   [opts.tunAddress]  — IPv4 TUN в формате CIDR
 * @param {string}   [opts.tunAddress6] — IPv6 TUN в формате CIDR
 */
function buildSingBox(profile, settings, opts = {}) {
  const include = settings.mode === 'include';
  const viaXray = settings.core === 'xray';
  const group = !viaXray && opts.group && opts.group.length > 1 ? opts.group : null;

  let proxyOutbounds;
  if (viaXray) {
    proxyOutbounds = [{ type: 'socks', tag: 'proxy', server: '127.0.0.1', server_port: settings.socksPort, version: '5' }];
  } else if (group) {
    proxyOutbounds = [
      {
        type: 'selector',
        tag: 'proxy',
        outbounds: group.map(memberTag),
        default: memberTag(profile),
        interrupt_exist_connections: true,
      },
      ...group.map(p => sbProxyOutbound(p, memberTag(p))),
    ];
  } else {
    proxyOutbounds = [sbProxyOutbound(profile)];
  }

  const serverDomains = [...new Set((group || [profile]).map(p => p.server).filter(h => h && !isIP(h)))];
  const matchers = appMatchers(settings.apps);
  const appTarget = include ? 'proxy' : 'direct';
  const dnsForApps = include ? 'dns-remote' : 'dns-direct';
  const dnsFinal = include
    ? (settings.dnsOthersViaVpn ? 'dns-remote' : 'dns-direct')
    : 'dns-remote';

  const tun4 = opts.tunAddress || '172.19.0.1/30';
  const tun6 = opts.tunAddress6 || 'fdfe:dcba:9876::1/126';

  const config = {
    log: { level: settings.logLevel || 'info', timestamp: true },
    dns: {
      servers: [
        { type: 'https', tag: 'dns-remote', server: settings.dnsRemote || '1.1.1.1', detour: 'proxy' },
        dnsDirectServer(settings),
      ],
      rules: [
        // Ядра и сами серверы резолвим напрямую, иначе петля
        { process_name: CORE_EXE, action: 'route', server: 'dns-direct' },
        ...(serverDomains.length ? [{ domain: serverDomains, action: 'route', server: 'dns-direct' }] : []),
        ...matchers.map(m => ({ ...m, action: 'route', server: dnsForApps })),
      ],
      final: dnsFinal,
      strategy: settings.ipv6 ? 'prefer_ipv4' : 'ipv4_only',
    },
    inbounds: [
      {
        type: 'tun',
        tag: 'tun-in',
        interface_name: 'Hello',
        address: settings.ipv6 ? [tun4, tun6] : [tun4],
        mtu: 9000,
        auto_route: true,
        strict_route: settings.strictRoute !== false,
        stack: settings.tunStack || 'mixed',
      },
    ],
    outbounds: [
      ...proxyOutbounds,
      { type: 'direct', tag: 'direct' },
    ],
    route: {
      auto_detect_interface: true,
      find_process: true,
      default_domain_resolver: 'dns-direct',
      rules: [
        { action: 'sniff' },
        { protocol: 'dns', action: 'hijack-dns' },
        // Трафик самих ядер (подключение к VPN-серверу) — всегда напрямую
        { process_name: CORE_EXE, action: 'route', outbound: 'direct' },
        { ip_is_private: true, action: 'route', outbound: 'direct' },
        ...matchers.map(m => ({ ...m, action: 'route', outbound: appTarget })),
      ],
      // include: всё остальное напрямую; exclude: всё остальное через VPN
      final: include ? 'direct' : 'proxy',
    },
  };
  if (opts.clashApi) {
    config.experimental = {
      clash_api: {
        external_controller: `127.0.0.1:${opts.clashApi.port}`,
        secret: opts.clashApi.secret,
      },
    };
  }
  return config;
}

/* ------------------------------- Xray ------------------------------- */

function xrayStream(p) {
  const s = { network: p.network === 'http' ? 'xhttp' : (p.network || 'tcp') };
  if (s.network === 'tcp') s.network = 'raw';

  const sni = p.sni || (isIP(p.server) ? '' : p.server);
  if (p.security === 'tls') {
    s.security = 'tls';
    s.tlsSettings = { serverName: sni || undefined, fingerprint: p.fp || 'chrome' };
    if (p.alpn && p.alpn.length) s.tlsSettings.alpn = p.alpn;
    if (p.allowInsecure) s.tlsSettings.allowInsecure = true;
  } else if (p.security === 'reality') {
    s.security = 'reality';
    s.realitySettings = {
      serverName: sni,
      fingerprint: p.fp || 'chrome',
      publicKey: p.pbk,
      shortId: p.sid || '',
      spiderX: p.spx || '',
    };
  } else {
    s.security = 'none';
  }

  switch (s.network) {
    case 'ws':
      s.wsSettings = { path: p.path || '/', host: p.host || undefined };
      break;
    case 'grpc':
      s.grpcSettings = { serviceName: p.serviceName || '', multiMode: p.mode === 'multi' };
      break;
    case 'httpupgrade':
      s.httpupgradeSettings = { path: p.path || '/', host: p.host || undefined };
      break;
    case 'xhttp':
      s.xhttpSettings = { path: p.path || '/', host: p.host || undefined, mode: p.mode || 'auto' };
      break;
    case 'raw':
      if (p.headerType === 'http') {
        s.rawSettings = { header: { type: 'http', request: { path: [p.path || '/'], headers: p.host ? { Host: [p.host] } : {} } } };
      }
      break;
    default:
      break;
  }
  return s;
}

function xrayOutbound(p) {
  switch (p.protocol) {
    case 'vless':
      return {
        tag: 'proxy',
        protocol: 'vless',
        settings: {
          vnext: [{
            address: p.server, port: p.port,
            users: [{ id: p.uuid, encryption: 'none', flow: p.flow || undefined }],
          }],
        },
        streamSettings: xrayStream(p),
      };
    case 'vmess':
      return {
        tag: 'proxy',
        protocol: 'vmess',
        settings: {
          vnext: [{
            address: p.server, port: p.port,
            users: [{ id: p.uuid, alterId: p.alterId || 0, security: p.cipher || 'auto' }],
          }],
        },
        streamSettings: xrayStream(p),
      };
    case 'trojan':
      return {
        tag: 'proxy',
        protocol: 'trojan',
        settings: { servers: [{ address: p.server, port: p.port, password: p.password }] },
        streamSettings: xrayStream(p),
      };
    case 'shadowsocks':
      return {
        tag: 'proxy',
        protocol: 'shadowsocks',
        settings: { servers: [{ address: p.server, port: p.port, method: p.method, password: p.password }] },
      };
    case 'hysteria2':
      throw new Error('Для Hysteria2 выберите ядро sing-box в настройках.');
    default:
      throw new Error(`Протокол ${p.protocol} не поддерживается Xray`);
  }
}

function buildXray(profile, settings) {
  return {
    log: { loglevel: settings.logLevel === 'debug' ? 'debug' : 'warning' },
    inbounds: [{
      tag: 'socks-in',
      listen: '127.0.0.1',
      port: settings.socksPort,
      protocol: 'socks',
      settings: { auth: 'noauth', udp: true },
      // sing-box отдаёт IP; сниффинг возвращает домен, чтобы сервер резолвил его сам
      sniffing: { enabled: true, destOverride: ['http', 'tls', 'quic'] },
    }],
    outbounds: [
      xrayOutbound(profile),
      { tag: 'direct', protocol: 'freedom' },
    ],
  };
}

/** Убирает undefined, чтобы JSON был чистым. */
function clean(obj) {
  return JSON.parse(JSON.stringify(obj));
}

module.exports = {
  buildSingBox: (p, s, o) => clean(buildSingBox(p, s, o)),
  autoGroup,
  memberTag,
  buildXray: (p, s) => clean(buildXray(p, s)),
  CORE_EXE,
};
