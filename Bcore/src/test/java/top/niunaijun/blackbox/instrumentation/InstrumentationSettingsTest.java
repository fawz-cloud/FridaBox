package top.niunaijun.blackbox.instrumentation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import org.junit.Test;

/** Verifies per-instance preference keys: instance 0 stays legacy, clones are isolated. */
public class InstrumentationSettingsTest {
    private static final String PREFIX = "package_mode_";
    private static final String PKG = "com.example.app";

    @Test
    public void instanceZeroKeepsLegacyPackageOnlyKey() {
        // Existing installs (pre multi-instance) must keep reading their saved mode.
        assertEquals(PREFIX + PKG, InstrumentationSettings.instanceKey(PREFIX, PKG, 0));
    }

    @Test
    public void clonedInstanceGetsUserSuffixedKey() {
        assertEquals(PREFIX + PKG + ":1", InstrumentationSettings.instanceKey(PREFIX, PKG, 1));
        assertEquals(PREFIX + PKG + ":7", InstrumentationSettings.instanceKey(PREFIX, PKG, 7));
    }

    @Test
    public void everyInstanceKeyIsDistinct() {
        String u0 = InstrumentationSettings.instanceKey(PREFIX, PKG, 0);
        String u1 = InstrumentationSettings.instanceKey(PREFIX, PKG, 1);
        String u2 = InstrumentationSettings.instanceKey(PREFIX, PKG, 2);
        assertNotEquals(u0, u1);
        assertNotEquals(u1, u2);
        assertNotEquals(u0, u2);
    }
}
