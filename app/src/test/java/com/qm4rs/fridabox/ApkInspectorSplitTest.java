package com.qm4rs.fridabox;

import static org.junit.Assert.assertThrows;

import org.junit.Test;

import java.util.Arrays;

import com.qm4rs.fridabox.ApkInspector.SplitMember;

public class ApkInspectorSplitTest {
    @Test
    public void baseWithTwoConfigSplitsIsAccepted() {
        ApkInspector.validateSplitSet(Arrays.asList(
                new SplitMember("com.example.app", 7, null),
                new SplitMember("com.example.app", 7, "config.arm64_v8a"),
                new SplitMember("com.example.app", 7, "config.xxhdpi")));
    }

    @Test
    public void twoBasesAreRejected() {
        assertThrows(IllegalArgumentException.class, () -> ApkInspector.validateSplitSet(Arrays.asList(
                new SplitMember("com.example.app", 7, null),
                new SplitMember("com.example.app", 7, ""))));
    }

    @Test
    public void mismatchedPackageNameIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ApkInspector.validateSplitSet(Arrays.asList(
                new SplitMember("com.example.app", 7, null),
                new SplitMember("com.other.app", 7, "config.arm64_v8a"))));
    }

    @Test
    public void mismatchedVersionCodeIsRejected() {
        assertThrows(IllegalArgumentException.class, () -> ApkInspector.validateSplitSet(Arrays.asList(
                new SplitMember("com.example.app", 7, null),
                new SplitMember("com.example.app", 8, "config.arm64_v8a"))));
    }
}
