package top.niunaijun.blackbox.fake.service.context.providers;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/** Verifies developer/debug settings are overridden, other settings pass through. */
public class EnvironmentSpoofTest {

    @Test
    public void spoofsAdbEnabledOnGlobalGet() {
        // call(callingPkg, "GET_global", "adb_enabled", extras)
        Object[] args = {"com.example.app", "GET_global", "adb_enabled", null};
        assertEquals("0", EnvironmentSpoof.resolveSpoofedValue(args));
    }

    @Test
    public void spoofsDeveloperOptionsAndMockLocationAcrossNamespaces() {
        assertEquals("0", EnvironmentSpoof.resolveSpoofedValue(
                new Object[]{"pkg", "GET_global", "development_settings_enabled", null}));
        assertEquals("0", EnvironmentSpoof.resolveSpoofedValue(
                new Object[]{"pkg", "GET_secure", "mock_location", null}));
        assertEquals("0", EnvironmentSpoof.resolveSpoofedValue(
                new Object[]{"pkg", "GET_global", "adb_wifi_enabled", null}));
    }

    @Test
    public void passesThroughUnspoofedSettings() {
        // A normal setting must not be intercepted.
        assertNull(EnvironmentSpoof.resolveSpoofedValue(
                new Object[]{"pkg", "GET_global", "airplane_mode_on", null}));
    }

    @Test
    public void ignoresNonGetCalls() {
        // A write (PUT_*) for adb_enabled must not be treated as a spoofed read.
        assertNull(EnvironmentSpoof.resolveSpoofedValue(
                new Object[]{"pkg", "PUT_global", "adb_enabled", null}));
    }

    @Test
    public void handlesNullAndEmpty() {
        assertNull(EnvironmentSpoof.resolveSpoofedValue(null));
        assertNull(EnvironmentSpoof.resolveSpoofedValue(new Object[]{}));
    }
}
