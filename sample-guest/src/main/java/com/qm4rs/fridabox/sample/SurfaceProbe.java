package com.qm4rs.fridabox.sample;

import android.content.Context;
import android.content.pm.PackageManager;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.UserManager;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * In-app detection-surface self-probe (the Android-side twin of
 * scripts/probe-suite.js). Emits the SAME JSON shape via stock Android APIs so
 * the normal-install + Palka Clean baseline can be captured without a Frida
 * gadget (a Frida probe cannot attach when no gadget is loaded). The result is
 * written to getExternalFilesDir()/palka-surface.json (no root, adb-pullable)
 * and fed to the same tools/probe_diff.py collect_leaks as the Frida probe.
 */
public final class SurfaceProbe {
    private static final String TAG = "FridaBox.Sample";
    private static final String OUT_NAME = "palka-surface.json";

    // Mirrors SUSPICIOUS_PATH / SUSPICIOUS_THREAD / PROPS in scripts/probe-suite.js.
    private static final Pattern SUSPICIOUS_PATH = Pattern.compile(
            "frida|gum|gadget|palka|guest-runtime|guest-agents|guest-runtimes|linjector|xposed|substrate|zygisk|memfd:",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SUSPICIOUS_THREAD = Pattern.compile(
            "gum-js-loop|gum-js-cond|gmain|gdbus|pool-frida|pool-spawner|frida|linjector",
            Pattern.CASE_INSENSITIVE);
    private static final String[] PROPS = {
            "ro.debuggable", "ro.secure", "ro.build.tags", "ro.build.type",
            "ro.build.fingerprint", "ro.build.selinux", "ro.boot.verifiedbootstate",
            "ro.boot.flash.locked", "ro.boot.veritymode", "ro.boot.vbmeta.device_state",
            "ro.product.model", "ro.product.manufacturer", "ro.kernel.qemu",
            "ro.hardware", "sys.oem_unlock_allowed"
    };

    private SurfaceProbe() {
    }

    private interface Section {
        Object build() throws Exception;
    }

    /** Capture the self-probe and write it next to the app's external files. Never throws. */
    public static File capture(Context context) {
        try {
            JSONObject result = new JSONObject();
            result.put("kind", "palka-probe");
            result.put("process", safe(SurfaceProbe::probeProcess));
            result.put("maps", safe(SurfaceProbe::probeMaps));
            result.put("modules", safe(SurfaceProbe::probeModules));
            result.put("threads", safe(SurfaceProbe::probeThreads));
            result.put("sockets", safe(SurfaceProbe::probeSockets));
            result.put("proc", safe(SurfaceProbe::probeProc));
            result.put("props", safe(SurfaceProbe::probeProps));
            final Context ctx = context;
            result.put("java", safe(() -> probeJava(ctx)));
            result.put("frida", JSONObject.NULL); // no gadget in a normal / Clean run

            File out = new File(context.getExternalFilesDir(null), OUT_NAME);
            try (FileWriter w = new FileWriter(out)) {
                w.write(result.toString(2));
            }
            Log.i(TAG, "SurfaceProbe wrote " + out.getAbsolutePath());
            return out;
        } catch (Throwable t) {
            Log.w(TAG, "SurfaceProbe failed", t);
            return null;
        }
    }

    private static Object safe(Section s) {
        try {
            return s.build();
        } catch (Throwable t) {
            try {
                return new JSONObject().put("error", String.valueOf(t.getMessage() != null ? t.getMessage() : t));
            } catch (Exception ignored) {
                return JSONObject.NULL;
            }
        }
    }

    private static JSONObject probeProcess() throws Exception {
        String arch = (Build.SUPPORTED_ABIS != null && Build.SUPPORTED_ABIS.length > 0)
                ? Build.SUPPORTED_ABIS[0] : "";
        return new JSONObject()
                .put("pid", android.os.Process.myPid())
                .put("arch", arch)
                .put("platform", "linux")
                .put("pointerSize", arch.contains("64") ? 8 : 4);
    }

    private static JSONObject probeMaps() throws Exception {
        String[] lines = readText("/proc/self/maps").split("\n", -1);
        JSONArray suspicious = new JSONArray();
        int execAnon = 0;
        for (String line : lines) {
            if (line.isEmpty()) {
                continue;
            }
            String[] parts = line.trim().split("\\s+");
            String perms = parts.length > 1 ? parts[1] : "";
            String path = pathOf(line);
            if (perms.indexOf('x') >= 0 && path.isEmpty()) {
                execAnon++; // executable mapping with no backing file
            }
            if (SUSPICIOUS_PATH.matcher(line).find()) {
                suspicious.put(line.trim());
            }
        }
        return new JSONObject()
                .put("total_lines", lines.length)
                .put("exec_anon_regions", execAnon)
                .put("suspicious", suspicious);
    }

    private static JSONObject probeModules() throws Exception {
        // No Frida: derive loaded modules from the file-backed mappings in maps.
        Set<String> seen = new LinkedHashSet<>();
        JSONArray suspicious = new JSONArray();
        for (String line : readText("/proc/self/maps").split("\n", -1)) {
            String path = pathOf(line);
            if (path.isEmpty() || path.charAt(0) != '/' || !seen.add(path)) {
                continue;
            }
            if (SUSPICIOUS_PATH.matcher(path).find()) {
                suspicious.put(new JSONObject().put("name", basename(path)).put("path", path));
            }
        }
        return new JSONObject().put("total", seen.size()).put("suspicious", suspicious);
    }

    private static JSONObject probeThreads() throws Exception {
        File[] tasks = new File("/proc/self/task").listFiles();
        JSONArray names = new JSONArray();
        JSONArray suspicious = new JSONArray();
        int total = tasks != null ? tasks.length : 0;
        if (tasks != null) {
            for (File t : tasks) {
                String name;
                try {
                    name = readText("/proc/self/task/" + t.getName() + "/comm").trim();
                } catch (Exception e) {
                    continue;
                }
                if (!name.isEmpty()) {
                    names.put(name);
                    if (SUSPICIOUS_THREAD.matcher(name).find()) {
                        suspicious.put(name);
                    }
                }
            }
        }
        return new JSONObject().put("total", total).put("names", names).put("suspicious", suspicious);
    }

    private static JSONObject probeSockets() throws Exception {
        JSONArray listening = new JSONArray();
        for (String p : new String[]{"/proc/net/tcp", "/proc/net/tcp6"}) {
            String text;
            try {
                text = readText(p);
            } catch (Exception e) {
                continue;
            }
            for (String line : text.split("\n", -1)) {
                String[] cols = line.trim().split("\\s+");
                // st == 0A means LISTEN; local_address in cols[1].
                if (cols.length > 3 && "0A".equals(cols[3])) {
                    listening.put(cols[1]);
                }
            }
        }
        return new JSONObject().put("listening", listening);
    }

    private static JSONObject probeProc() throws Exception {
        JSONObject out = new JSONObject();
        out.put("cmdline", safe(() -> readText("/proc/self/cmdline").replace('\0', ' ').trim()));
        out.put("comm", safe(() -> readText("/proc/self/comm").trim()));
        out.put("status", safe(() -> {
            JSONObject picks = new JSONObject();
            for (String line : readText("/proc/self/status").split("\n", -1)) {
                int colon = line.indexOf(':');
                if (colon <= 0) {
                    continue;
                }
                String key = line.substring(0, colon);
                if (key.equals("Uid") || key.equals("Gid") || key.equals("Threads")
                        || key.equals("TracerPid") || key.equals("Seccomp")
                        || key.equals("State") || key.equals("Name")) {
                    picks.put(key, line.substring(colon + 1).trim());
                }
            }
            return picks;
        }));
        return out;
    }

    private static JSONObject probeProps() throws Exception {
        Method get = Class.forName("android.os.SystemProperties").getMethod("get", String.class);
        JSONObject out = new JSONObject();
        for (String name : PROPS) {
            try {
                out.put(name, (String) get.invoke(null, name));
            } catch (Exception e) {
                out.put(name, JSONObject.NULL);
            }
        }
        return out;
    }

    private static JSONObject probeJava(Context context) throws Exception {
        JSONObject out = new JSONObject();
        out.put("available", true);
        PackageManager pm = context.getPackageManager();
        String pkg = context.getPackageName();
        out.put("packageName", pkg);
        out.put("uid", context.getApplicationInfo().uid);
        String installer;
        try {
            installer = pm.getInstallerPackageName(pkg);
        } catch (Exception e) {
            installer = null;
        }
        out.put("installer", installer != null ? installer : JSONObject.NULL);
        out.put("build", new JSONObject()
                .put("TAGS", String.valueOf(Build.TAGS))
                .put("TYPE", String.valueOf(Build.TYPE))
                .put("FINGERPRINT", String.valueOf(Build.FINGERPRINT)));
        try {
            UserManager um = (UserManager) context.getSystemService(Context.USER_SERVICE);
            if (um != null) {
                out.put("userName", String.valueOf(um.getUserName()));
            }
        } catch (Exception ignored) {
        }
        try {
            WifiManager wifi = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifi != null && wifi.getConnectionInfo() != null) {
                out.put("ssid", String.valueOf(wifi.getConnectionInfo().getSSID()));
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    /** Path portion of a maps line: from the first '/' or, failing that, the first '['. */
    private static String pathOf(String line) {
        int slash = line.indexOf('/');
        if (slash >= 0) {
            return line.substring(slash);
        }
        int bracket = line.indexOf('[');
        return bracket >= 0 ? line.substring(bracket) : "";
    }

    private static String basename(String path) {
        int slash = path.lastIndexOf('/');
        return slash >= 0 ? path.substring(slash + 1) : path;
    }

    private static String readText(String path) throws Exception {
        try (FileInputStream in = new FileInputStream(path)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
            }
            return new String(out.toByteArray(), StandardCharsets.UTF_8);
        }
    }
}
