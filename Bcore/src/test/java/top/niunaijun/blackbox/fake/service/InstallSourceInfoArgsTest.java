package top.niunaijun.blackbox.fake.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import org.junit.Test;

/**
 * Host-pure coverage for the InstallSourceInfo constructor arg sizing used by
 * {@link IPackageManagerProxy.GetInstallSourceInfo}. The real constructor arity
 * differs across API 30-33 (4 params) and 34+ (6 params, adds an int), so the
 * only thing worth testing is that the installer lands at index 3 and int
 * params are zeroed instead of left null (null -> NPE on newInstance).
 */
public class InstallSourceInfoArgsTest {

    // API 30-33: (String, SigningInfo, String, String)
    @Test
    public void api30SetsInstallerAtIndexThreeAndNullsRest() {
        Class<?>[] params = {String.class, Object.class, String.class, String.class};
        Object[] args = IPackageManagerProxy.buildInstallSourceArgs(params, 3, "com.android.vending");

        assertEquals(4, args.length);
        assertEquals("com.android.vending", args[3]);
        assertNull(args[0]);
        assertNull(args[1]);
        assertNull(args[2]);
    }

    // API 34+: (String, SigningInfo, String, String, String, int)
    @Test
    public void api34ZeroesIntParamAndKeepsInstallerAtIndexThree() {
        Class<?>[] params = {String.class, Object.class, String.class, String.class, String.class, int.class};
        Object[] args = IPackageManagerProxy.buildInstallSourceArgs(params, 3, "com.android.vending");

        assertEquals(6, args.length);
        assertEquals("com.android.vending", args[3]);
        assertNull(args[4]);
        assertEquals(0, args[5]); // int packageSource must be boxed 0, not null
    }
}
