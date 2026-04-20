// _loader.js — shared helpers + config for all MxProtector probes.
//
// The Python side composes the final script by replacing the literal
// `__MX_CONFIG__` with a JSON literal (valid JSON is valid JS) and
// appending the enabled probe files after this loader.
//
// Exposed globals:
//   globalThis.MxCfg  — config object (probes, mem_ranges, …)
//   globalThis.MxEvt  — { send(kind, payload) }
//
// The loader also emits a `loader_ready` event so the host can tell
// whether the script made it past initial composition.

(function mxTracingLoader() {
  'use strict';

  var config;
  try {
    config = __MX_CONFIG__;
  } catch (e) {
    config = { probes: [] };
  }
  if (!config || typeof config !== 'object') {
    config = { probes: [] };
  }
  if (!Array.isArray(config.probes)) {
    config.probes = [];
  }

  globalThis.MxCfg = config;

  globalThis.MxEvt = {
    send: function (kind, payload) {
      send({ kind: kind, t: Date.now(), payload: payload || {} });
    }
  };

  MxEvt.send('loader_ready', { probes: config.probes.slice() });
})();
