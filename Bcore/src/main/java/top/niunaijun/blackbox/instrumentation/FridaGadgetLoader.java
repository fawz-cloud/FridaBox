package top.niunaijun.blackbox.instrumentation;

import android.util.Log;

import java.io.File;
import java.util.concurrent.atomic.AtomicBoolean;

/** Loads Frida Gadget at most once in the current Linux process. */
public final class FridaGadgetLoader {
    private static final String TAG = "FridaBox.Gadget";
    private static final AtomicBoolean ATTEMPTED = new AtomicBoolean(false);
    private static final Object LOAD_LOCK = new Object();
    private static volatile boolean loaded;

    private FridaGadgetLoader() {
    }

    /** Listener mode starts immediately; autonomous scripts wait for the guest lifecycle. */
    public static boolean loadAtProcessBind() {
        String packageName = GuestRuntimeRegistry.getGuestPackageName();
        String mode = InstrumentationSettings.getModeForPackage(packageName);
        if (shouldDeferAtBind(mode)) {
            Log.i(TAG, "Deferring on-device agent until the guest application is ready");
            return false;
        }
        return loadIfEnabled();
    }

    public static boolean loadIfEnabled() {
        String packageName = GuestRuntimeRegistry.getGuestPackageName();
        String mode = InstrumentationSettings.getModeForPackage(packageName);
        GadgetLoadPlan plan = decide(GuestRuntimeRegistry.isInstrumentationEnabled(), mode,
                GuestRuntimeRegistry.isPrimaryProcess());
        if (plan == GadgetLoadPlan.DISABLED) {
            Log.i(TAG, "Instrumentation disabled for this guest process");
            return false;
        }
        if (plan == GadgetLoadPlan.SKIP_SECONDARY) {
            Log.i(TAG, "Skipping on-device agent in secondary process "
                    + GuestRuntimeRegistry.getGuestProcessName());
            return false;
        }
        if (loaded) return true;
        synchronized (LOAD_LOCK) {
            if (loaded) return true;
            if (!ATTEMPTED.compareAndSet(false, true)) return false;
            try {
                InstrumentationStatusStore.recordBinding();
                if (InstrumentationSettings.MODE_LOCAL_SCRIPT.equals(mode)) {
                    String scriptPath = InstrumentationSettings.getScriptPathForPackage(packageName);
                    File runtime = LocalScriptGadgetRuntime.prepare(packageName, scriptPath);
                    Log.i(TAG, "Loading on-device Frida agent for " + GuestRuntimeRegistry.getGuestProcessName());
                    System.load(runtime.getAbsolutePath());
                } else {
                    Log.i(TAG, "Loading Frida Gadget listener for " + GuestRuntimeRegistry.getGuestProcessName());
                    File runtime = DownloadedGadgetRuntime.prepareListener(packageName);
                    System.load(runtime.getAbsolutePath());
                }
                loaded = true;
                InstrumentationStatusStore.recordLoaded();
                Log.i(TAG, "Frida Gadget loaded");
                return true;
            } catch (UnsatisfiedLinkError | SecurityException error) {
                GuestRuntimeRegistry.setLastError(error);
                InstrumentationStatusStore.recordError(GuestRuntimeRegistry.getLastError());
                Log.e(TAG, "Frida Gadget load failed; guest will continue", error);
            } catch (Throwable error) {
                GuestRuntimeRegistry.setLastError(error);
                InstrumentationStatusStore.recordError(GuestRuntimeRegistry.getLastError());
                Log.e(TAG, "Unexpected Frida Gadget initialization failure; guest will continue", error);
            }
            return false;
        }
    }

    public static boolean isLoaded() {
        return loaded;
    }

    /** What loadIfEnabled() should do for a given (enabled, mode, primary) triple. */
    enum GadgetLoadPlan {
        LOAD_LISTENER, LOAD_LOCAL_SCRIPT, DEFER_LOCAL_SCRIPT, SKIP_SECONDARY, DISABLED
    }

    /** At process bind the on-device agent waits for the guest lifecycle; the listener loads now. */
    static boolean shouldDeferAtBind(String mode) {
        return InstrumentationSettings.MODE_LOCAL_SCRIPT.equals(mode);
    }

    /** Pure load decision, no side effects, so it is unit-testable off-device. */
    static GadgetLoadPlan decide(boolean enabled, String mode, boolean primary) {
        if (!enabled || InstrumentationSettings.MODE_CLEAN.equals(mode)) {
            return GadgetLoadPlan.DISABLED;
        }
        if (InstrumentationSettings.MODE_LOCAL_SCRIPT.equals(mode) && !primary) {
            return GadgetLoadPlan.SKIP_SECONDARY;
        }
        if (InstrumentationSettings.MODE_LOCAL_SCRIPT.equals(mode)) {
            return GadgetLoadPlan.LOAD_LOCAL_SCRIPT;
        }
        return GadgetLoadPlan.LOAD_LISTENER;
    }
}
