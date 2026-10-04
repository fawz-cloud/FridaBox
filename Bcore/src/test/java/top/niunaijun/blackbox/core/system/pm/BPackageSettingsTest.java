package top.niunaijun.blackbox.core.system.pm;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class BPackageSettingsTest {

    @Test
    public void usesConfMtimeWhenAvailable() {
        assertEquals(1700000000000L, BPackageSettings.resolveInstallTime(1700000000000L, 999L));
    }

    @Test
    public void fallsBackToSentinelWhenMtimeMissing() {
        assertEquals(42L, BPackageSettings.resolveInstallTime(0L, 42L));
        assertEquals(42L, BPackageSettings.resolveInstallTime(-5L, 42L));
    }

    @Test
    public void neverSurfacesEpochZero() {
        // The whole point of the field: a pre-installTime clone must not report firstInstallTime == 0.
        long resolved = BPackageSettings.resolveInstallTime(0L, 42L);
        assertEquals(42L, resolved);
    }
}
