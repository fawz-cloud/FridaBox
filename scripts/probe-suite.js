'use strict';

/*
 * Palka detection-surface probe (P0 regression laboratory).
 *
 * Dumps, as one structured JSON object, the surfaces a guest app uses to detect
 * instrumentation / virtualization, so the same probe can be run against a
 * normal install, Palka Clean mode, and each instrumented mode, then diffed with
 * tools/probe_diff.py.
 *
 * This is a RAW Frida script (no frida-java-bridge import) so it runs directly:
 *     frida -U gadget -l scripts/probe-suite.js
 * It covers the native / /proc / system-property surfaces without Java. The Java
 * section runs only when a `Java` global is already present (e.g. inside an
 * on-device agent that injected the bridge); otherwise it is reported absent.
 *
 * Output: a single line  PALKA_PROBE <json>  on the console, and a matching
 * send({kind:'palka-probe', value:<json>}) message for the computer-side client.
 */

var SUSPICIOUS_PATH = /frida|gum|gadget|palka|guest-runtime|guest-agents|guest-runtimes|linjector|xposed|substrate|zygisk|memfd:/i;
var SUSPICIOUS_THREAD = /gum-js-loop|gum-js-cond|gmain|gdbus|pool-frida|pool-spawner|frida|linjector/i;
var PROPS = [
  'ro.debuggable', 'ro.secure', 'ro.build.tags', 'ro.build.type',
  'ro.build.fingerprint', 'ro.build.selinux', 'ro.boot.verifiedbootstate',
  'ro.boot.flash.locked', 'ro.boot.veritymode', 'ro.boot.vbmeta.device_state',
  'ro.product.model', 'ro.product.manufacturer', 'ro.kernel.qemu',
  'ro.hardware', 'sys.oem_unlock_allowed'
];

function safe(fn, fallback) {
  try { return fn(); } catch (e) { return { error: String(e && e.message ? e.message : e), fallback: fallback }; }
}

function readText(path) {
  return File.readAllText(path);
}

function probeMaps() {
  var text = readText('/proc/self/maps');
  var lines = text.split('\n');
  var suspicious = [];
  var execAnon = 0;
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line) continue;
    var perms = line.split(/\s+/)[1] || '';
    var path = line.indexOf('/') >= 0 ? line.slice(line.indexOf('/')) : (line.indexOf('[') >= 0 ? line.slice(line.indexOf('[')) : '');
    if (perms.indexOf('x') >= 0 && path === '') execAnon++;         // executable mapping with no backing file
    if (SUSPICIOUS_PATH.test(line)) suspicious.push(line.trim());
  }
  return { total_lines: lines.length, exec_anon_regions: execAnon, suspicious: suspicious };
}

function probeModules() {
  var mods = Process.enumerateModules();
  var suspicious = [];
  for (var i = 0; i < mods.length; i++) {
    if (SUSPICIOUS_PATH.test(mods[i].name) || SUSPICIOUS_PATH.test(mods[i].path)) {
      suspicious.push({ name: mods[i].name, path: mods[i].path });
    }
  }
  return { total: mods.length, suspicious: suspicious };
}

function probeThreads() {
  var threads = Process.enumerateThreads();
  var names = [];
  var suspicious = [];
  for (var i = 0; i < threads.length; i++) {
    var name = null;
    try { name = readText('/proc/self/task/' + threads[i].id + '/comm').trim(); } catch (e) {}
    if (name) {
      names.push(name);
      if (SUSPICIOUS_THREAD.test(name)) suspicious.push(name);
    }
  }
  return { total: threads.length, names: names, suspicious: suspicious };
}

function probeSockets() {
  var listeners = [];
  ['/proc/net/tcp', '/proc/net/tcp6'].forEach(function (p) {
    var text;
    try { text = readText(p); } catch (e) { return; }
    text.split('\n').forEach(function (line) {
      var cols = line.trim().split(/\s+/);
      // st == 0A means LISTEN; local_address in cols[1]
      if (cols.length > 3 && cols[3] === '0A') {
        listeners.push(cols[1]);
      }
    });
  });
  return { listening: listeners };
}

function probeProc() {
  var out = {};
  out.cmdline = safe(function () { return readText('/proc/self/cmdline').replace(/\0/g, ' ').trim(); });
  out.comm = safe(function () { return readText('/proc/self/comm').trim(); });
  out.status = safe(function () {
    var picks = {};
    readText('/proc/self/status').split('\n').forEach(function (line) {
      var m = line.match(/^(Uid|Gid|Threads|TracerPid|Seccomp|State|Name):\s*(.+)$/);
      if (m) picks[m[1]] = m[2].trim();
    });
    return picks;
  });
  return out;
}

function probeProps() {
  var get = null;
  try {
    var addr = Module.findGlobalExportByName('__system_property_get');
    if (addr) get = new NativeFunction(addr, 'int', ['pointer', 'pointer']);
  } catch (e) {}
  var out = {};
  if (!get) return { error: '__system_property_get unavailable' };
  var buf = Memory.alloc(96);
  PROPS.forEach(function (name) {
    try {
      var n = Memory.allocUtf8String(name);
      get(n, buf);
      out[name] = buf.readUtf8String();
    } catch (e) { out[name] = null; }
  });
  return out;
}

function probeJava() {
  if (typeof Java === 'undefined' || !Java.available) return { available: false };
  var out = { available: true };
  try {
    Java.perform(function () {
      var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
      var pm = ctx.getPackageManager();
      var pkg = ctx.getPackageName();
      out.packageName = pkg.toString();
      out.uid = ctx.getApplicationInfo().uid.value;
      try { out.installer = '' + pm.getInstallerPackageName(pkg); } catch (e) { out.installer = null; }
      var Build = Java.use('android.os.Build');
      out.build = { TAGS: '' + Build.TAGS.value, TYPE: '' + Build.TYPE.value, FINGERPRINT: '' + Build.FINGERPRINT.value };
      try {
        var um = Java.use('android.os.UserManager');
        var inst = ctx.getSystemService('user');
        out.userName = '' + Java.cast(inst, um).getUserName();
      } catch (e) {}
      try {
        var wifi = Java.cast(ctx.getSystemService('wifi'), Java.use('android.net.wifi.WifiManager'));
        out.ssid = '' + wifi.getConnectionInfo().getSSID();
      } catch (e) {}
    });
  } catch (e) { out.error = String(e && e.message ? e.message : e); }
  return out;
}

function run() {
  var result = {
    kind: 'palka-probe',
    process: safe(function () { return { pid: Process.id, arch: Process.arch, platform: Process.platform, pointerSize: Process.pointerSize }; }),
    maps: safe(probeMaps),
    modules: safe(probeModules),
    threads: safe(probeThreads),
    sockets: safe(probeSockets),
    proc: safe(probeProc),
    props: safe(probeProps),
    java: safe(probeJava)
  };
  try { console.log('PALKA_PROBE ' + JSON.stringify(result)); } catch (e) {}
  try { send(result); } catch (e) {}
  return result;
}

run();
