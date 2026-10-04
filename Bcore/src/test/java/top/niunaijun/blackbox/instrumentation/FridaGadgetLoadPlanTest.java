package top.niunaijun.blackbox.instrumentation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import top.niunaijun.blackbox.instrumentation.FridaGadgetLoader.GadgetLoadPlan;

public class FridaGadgetLoadPlanTest {
    private static final String COMPUTER = InstrumentationSettings.MODE_COMPUTER;
    private static final String LOCAL_SCRIPT = InstrumentationSettings.MODE_LOCAL_SCRIPT;
    private static final String CLEAN = InstrumentationSettings.MODE_CLEAN;

    @Test
    public void listenerModeLoadsInEveryProcess() {
        assertEquals(GadgetLoadPlan.LOAD_LISTENER, FridaGadgetLoader.decide(true, COMPUTER, true));
        assertEquals(GadgetLoadPlan.LOAD_LISTENER, FridaGadgetLoader.decide(true, COMPUTER, false));
    }

    @Test
    public void localScriptLoadsInPrimaryAndSkipsSecondary() {
        assertEquals(GadgetLoadPlan.LOAD_LOCAL_SCRIPT, FridaGadgetLoader.decide(true, LOCAL_SCRIPT, true));
        assertEquals(GadgetLoadPlan.SKIP_SECONDARY, FridaGadgetLoader.decide(true, LOCAL_SCRIPT, false));
    }

    @Test
    public void disabledGuestNeverLoads() {
        assertEquals(GadgetLoadPlan.DISABLED, FridaGadgetLoader.decide(false, COMPUTER, true));
        assertEquals(GadgetLoadPlan.DISABLED, FridaGadgetLoader.decide(false, COMPUTER, false));
        assertEquals(GadgetLoadPlan.DISABLED, FridaGadgetLoader.decide(false, LOCAL_SCRIPT, true));
    }

    @Test
    public void cleanModeIsAlwaysDisabled() {
        assertEquals(GadgetLoadPlan.DISABLED, FridaGadgetLoader.decide(true, CLEAN, true));
        assertEquals(GadgetLoadPlan.DISABLED, FridaGadgetLoader.decide(true, CLEAN, false));
        assertEquals(GadgetLoadPlan.DISABLED, FridaGadgetLoader.decide(false, CLEAN, true));
    }

    @Test
    public void unknownModeFallsBackToListener() {
        assertEquals(GadgetLoadPlan.LOAD_LISTENER, FridaGadgetLoader.decide(true, null, true));
        assertEquals(GadgetLoadPlan.LOAD_LISTENER, FridaGadgetLoader.decide(true, "something_else", false));
    }

    @Test
    public void onlyLocalScriptDefersAtBind() {
        assertTrue(FridaGadgetLoader.shouldDeferAtBind(LOCAL_SCRIPT));
        assertFalse(FridaGadgetLoader.shouldDeferAtBind(COMPUTER));
        assertFalse(FridaGadgetLoader.shouldDeferAtBind(CLEAN));
        assertFalse(FridaGadgetLoader.shouldDeferAtBind(null));
    }
}
