'use strict';
/**
 * Прослойка: тот же window.api, что был в Electron-версии (preload.js),
 * но поверх команд и событий Tauri.
 */
(() => {
  const { invoke } = window.__TAURI__.core;
  const { listen } = window.__TAURI__.event;

  const call = (cmd, args) => invoke(cmd, args).catch(err => {
    throw new Error(typeof err === 'string' ? err : (err && err.message) || String(err));
  });
  const on = (name, cb) => { listen(name, e => cb(e.payload)); };

  window.api = {
    getState: () => call('get_state'),
    getLogs: () => call('get_logs'),
    clearLogs: () => call('clear_logs'),
    collectLogs: () => call('collect_logs'),
    relaunchAdmin: () => call('relaunch_admin'),
    openBinDir: () => call('open_bin_dir'),

    updateSettings: patch => call('update_settings', { patch }),

    importProfiles: text => call('import_profiles', { text }),
    removeProfile: id => call('remove_profile', { id }),
    selectProfile: id => call('select_profile', { id }),
    setProfileAuto: (id, included) => call('set_profile_auto', { id, included }),
    pingProfiles: () => call('ping_profiles'),
    refreshSubs: id => call('refresh_subs', { id: id ?? null }),
    removeSub: id => call('remove_sub', { id }),
    openSubLink: (id, kind) => call('open_sub_link', { id, kind }),

    listProcesses: () => call('list_processes'),
    pickExe: () => call('pick_exe'),
    setApps: apps => call('set_apps', { apps }),
    appIcons: () => call('app_icons'),

    connect: () => call('connect'),
    disconnect: () => call('disconnect'),
    restart: () => call('restart'),

    onLog: cb => on('log', cb),
    onState: cb => on('vpn:state', cb),
    onSwitch: cb => on('vpn:switch', cb),
    onAllDown: cb => on('vpn:allDown', () => cb()),
    onHealth: cb => on('vpn:health', cb),
  };
})();
