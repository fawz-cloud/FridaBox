package top.niunaijun.blackbox.fake.service.context.providers;

import android.os.Bundle;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Hides developer/debug environment signals from guest apps.
 *
 * Apps probe for a "developer device" by reading Settings.Global / Settings.Secure
 * values such as adb_enabled (USB debugging) and development_settings_enabled
 * (Developer options). Those reads are serviced by the settings provider's
 * {@code call(method, name, ...)} where method is GET_global / GET_secure /
 * GET_system and the return Bundle carries the value under key "value"
 * (Settings.NameValueTable.VALUE).
 *
 * This intercepts those reads for the keys below and returns a clean value, so the
 * guest sees a non-developer device. It only overrides the listed keys; every
 * other setting falls through to the real provider.
 */
public final class EnvironmentSpoof {
    // Settings.NameValueTable.VALUE
    private static final String VALUE = "value";

    // The settings provider read methods (android.provider.Settings.CALL_METHOD_GET_*).
    private static final String[] GET_METHODS = {
            "GET_global", "GET_secure", "GET_system", "GET_config",
    };

    // Default spoof set. Extend here for more signals ("dan lain lain").
    private static final Map<String, String> SPOOF;
    static {
        Map<String, String> m = new HashMap<>();
        m.put("adb_enabled", "0");                  // USB debugging
        m.put("development_settings_enabled", "0"); // Developer options
        m.put("adb_wifi_enabled", "0");             // Wireless debugging
        m.put("mock_location", "0");                // Legacy mock-location flag
        SPOOF = Collections.unmodifiableMap(m);
    }

    private EnvironmentSpoof() {
    }

    /**
     * If {@code args} describe a settings GET for one of the spoofed keys, return a
     * Bundle with the spoofed value; otherwise null (let the real provider answer).
     */
    public static Bundle spoofSettingsCall(Object[] args) {
        String value = resolveSpoofedValue(args);
        if (value == null) return null;
        Bundle bundle = new Bundle();
        bundle.putString(VALUE, value);
        return bundle;
    }

    /**
     * Pure resolver (no Android types, unit-testable): returns the spoofed value for
     * a settings GET of a spoofed key, or null to let the real provider answer.
     */
    static String resolveSpoofedValue(Object[] args) {
        if (args == null) return null;
        boolean isGet = false;
        String name = null;
        for (Object a : args) {
            if (!(a instanceof String)) continue;
            String s = (String) a;
            if (!isGet && isGetMethod(s)) {
                isGet = true;
                continue;
            }
            if (SPOOF.containsKey(s)) {
                name = s;
            }
        }
        if (!isGet || name == null) return null;
        return SPOOF.get(name);
    }

    private static boolean isGetMethod(String s) {
        for (String m : GET_METHODS) {
            if (m.equals(s)) return true;
        }
        return false;
    }
}
