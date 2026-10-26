'use strict';
const { contextBridge, ipcRenderer } = require('electron');

const invoke = (ch, ...args) => ipcRenderer.invoke(ch, ...args).catch(err => {
  // Убираем техническую приставку Electron «Error invoking remote method …: Error: »
  const msg = String(err && err.message || err).replace(/^Error invoking remote method '[^']+': (Error: )?/, '');
  throw new Error(msg);
});

contextBridge.exposeInMainWorld('api', {
  getState: () => invoke('state:get'),
  getLogs: () => invoke('logs:get'),
  clearLogs: () => invoke('logs:clear'),
  collectLogs: () => invoke('logs:collect'),
  relaunchAdmin: () => invoke('app:relaunchAdmin'),
  openBinDir: () => invoke('app:openBinDir'),

  updateSettings: patch => invoke('settings:update', patch),

  importProfiles: text => invoke('profiles:import', text),
  removeProfile: id => invoke('profiles:remove', id),
  selectProfile: id => invoke('profiles:select', id),
  setProfileAuto: (id, included) => invoke('profiles:setAuto', id, included),
  pingProfiles: ids => invoke('profiles:ping', ids),
  refreshSubs: id => invoke('subs:refresh', id),
  removeSub: id => invoke('subs:remove', id),

  listProcesses: () => invoke('proc:list'),
  pickExe: () => invoke('proc:pickExe'),
  setApps: apps => invoke('apps:set', apps),
  appIcons: () => invoke('apps:icons'),

  connect: () => invoke('vpn:connect'),
  disconnect: () => invoke('vpn:disconnect'),
  restart: () => invoke('vpn:restart'),

  onLog: cb => ipcRenderer.on('log', (_e, d) => cb(d)),
  onState: cb => ipcRenderer.on('vpn:state', (_e, d) => cb(d)),
  onSwitch: cb => ipcRenderer.on('vpn:switch', (_e, d) => cb(d)),
  onAllDown: cb => ipcRenderer.on('vpn:allDown', () => cb()),
  onHealth: cb => ipcRenderer.on('vpn:health', (_e, d) => cb(d)),
});
