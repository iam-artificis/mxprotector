// mem_region.js — per-range memory access detection.
//
// MxCfg.mem_ranges: [{ role: 'packer', rva: 0x1000, size: 0x2000 }, …]
//
// The main module's image base is resolved at load time so the Python
// side only passes RVA + size (no 64-bit address wrangling). On first
// access to a watched page, a `section_access` event fires with the
// role and in-range offset. Per-access events are intentionally not
// throttled — Phase 2 fixtures are small; later phases gate by probe
// config if it becomes noisy.

(function mxProbeMemRegion() {
  'use strict';

  if (!globalThis.MxCfg || !globalThis.MxEvt) return;
  if ((MxCfg.probes || []).indexOf('mem_region') === -1) return;

  var ranges = MxCfg.mem_ranges || [];
  if (ranges.length === 0) {
    MxEvt.send('probe_loaded', { name: 'mem_region', watched: 0 });
    return;
  }

  var modules = Process.enumerateModules();
  if (modules.length === 0) {
    MxEvt.send('probe_error', { name: 'mem_region', err: 'no modules' });
    return;
  }
  var imageBase = modules[0].base;

  var watchlist = [];
  ranges.forEach(function (r, idx) {
    if (!r || typeof r.rva !== 'number' || typeof r.size !== 'number') return;
    if (r.size === 0) return;
    watchlist.push({
      role: String(r.role || '?'),
      base: imageBase.add(r.rva),
      size: r.size,
      idx:  idx
    });
  });

  if (watchlist.length === 0) {
    MxEvt.send('probe_loaded', { name: 'mem_region', watched: 0 });
    return;
  }

  try {
    MemoryAccessMonitor.enable(
      watchlist.map(function (w) { return { base: w.base, size: w.size }; }),
      {
        onAccess: function (details) {
          var addr = details.address;
          for (var i = 0; i < watchlist.length; i++) {
            var w = watchlist[i];
            if (addr.compare(w.base) >= 0 && addr.compare(w.base.add(w.size)) < 0) {
              MxEvt.send('section_access', {
                role:      w.role,
                operation: details.operation,
                offset:    addr.sub(w.base).toInt32()
              });
              return;
            }
          }
        }
      }
    );
  } catch (e) {
    MxEvt.send('probe_error', { name: 'mem_region', err: String(e) });
    return;
  }

  MxEvt.send('probe_loaded', { name: 'mem_region', watched: watchlist.length });
})();
