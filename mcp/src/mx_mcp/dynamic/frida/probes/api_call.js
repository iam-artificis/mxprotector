// api_call.js — intercepts a small allowlist of Windows APIs that
// matter to MxProtector invariants: anti-debug probes, loader-time
// callbacks, VirtualProtect/VirtualAlloc (used by packer decrypt +
// reprotect), VEH registration.
//
// Emits one event per call with { mod, fn }. Arguments and return
// values are not captured yet — a later phase (anti-debug invariant)
// will add targeted captures for NtQueryInformationProcess etc.

(function mxProbeApiCall() {
  'use strict';

  if (!globalThis.MxCfg || !globalThis.MxEvt) return;
  if ((MxCfg.probes || []).indexOf('api_call') === -1) return;

  var targets = [
    ['kernel32.dll', 'IsDebuggerPresent'],
    ['kernel32.dll', 'CheckRemoteDebuggerPresent'],
    ['kernel32.dll', 'OutputDebugStringA'],
    ['kernel32.dll', 'OutputDebugStringW'],
    ['kernel32.dll', 'LoadLibraryA'],
    ['kernel32.dll', 'LoadLibraryW'],
    ['kernel32.dll', 'LoadLibraryExA'],
    ['kernel32.dll', 'LoadLibraryExW'],
    ['kernel32.dll', 'GetProcAddress'],
    ['kernel32.dll', 'VirtualProtect'],
    ['kernel32.dll', 'VirtualAlloc'],
    ['ntdll.dll',    'NtQueryInformationProcess'],
    ['ntdll.dll',    'NtSetInformationThread'],
    ['ntdll.dll',    'NtClose'],
    ['ntdll.dll',    'RtlAddVectoredExceptionHandler']
  ];

  // Frida 17 removed the two-arg `Module.findExportByName`. The
  // replacement is `Module.findGlobalExportByName(name)` which
  // searches all loaded modules and returns the first match. For our
  // hardcoded API names (IsDebuggerPresent, VirtualProtect, …) the
  // first match is always the owning module we expect.
  var attached = 0;
  targets.forEach(function (t) {
    var mod = t[0];
    var fn  = t[1];
    var addr = Module.findGlobalExportByName(fn);
    if (!addr) return;
    try {
      Interceptor.attach(addr, {
        onEnter: function () {
          MxEvt.send('api_call', { mod: mod, fn: fn });
        }
      });
      attached++;
    } catch (e) {
      MxEvt.send('probe_error', { name: 'api_call', fn: fn, err: String(e) });
    }
  });

  MxEvt.send('probe_loaded', { name: 'api_call', attached: attached });
})();
