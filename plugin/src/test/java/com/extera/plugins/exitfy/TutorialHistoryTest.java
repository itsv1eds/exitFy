package com.extera.plugins.exitfy;

import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import static org.junit.Assert.*;

public class TutorialHistoryTest {
    private static final String CLIENT = "client", ROOT = "dashboard", SERVERS = "servers", PREFS = "preferences";
    private static boolean plugin(String screen) { return screen.equals(ROOT) || screen.equals(SERVERS) || screen.equals(PREFS); }

    @Test public void replayFindsTheDashboardAlreadyBelowSettings() {
        List<String> stack = Arrays.asList(CLIENT, ROOT, PREFS);
        assertEquals(1, TutorialHistory.rootIndex(stack, PREFS, ROOT::equals, TutorialHistoryTest::plugin));
        assertTrue(TutorialHistory.intermediateScreens(stack, ROOT, PREFS, TutorialHistoryTest::plugin).isEmpty());
    }

    @Test public void cleanupRemovesOnlyIntermediatePluginScreens() {
        List<String> stack = Arrays.asList(CLIENT, ROOT, SERVERS, PREFS);
        assertEquals(Arrays.asList(SERVERS), TutorialHistory.intermediateScreens(stack, ROOT, PREFS, TutorialHistoryTest::plugin));
    }

    @Test public void anotherClientScreenPreventsRootReuseAndCleanup() {
        List<String> stack = Arrays.asList(CLIENT, ROOT, "chat", PREFS);
        assertEquals(-1, TutorialHistory.rootIndex(stack, PREFS, ROOT::equals, TutorialHistoryTest::plugin));
        assertTrue(TutorialHistory.intermediateScreens(stack, ROOT, PREFS, TutorialHistoryTest::plugin).isEmpty());
    }

    @Test public void absentOrCurrentRootNeedsNoScreensRemoved() {
        List<String> stack = Arrays.asList(CLIENT, ROOT);
        assertEquals(1, TutorialHistory.rootIndex(stack, ROOT, ROOT::equals, TutorialHistoryTest::plugin));
        assertTrue(TutorialHistory.intermediateScreens(stack, ROOT, ROOT, TutorialHistoryTest::plugin).isEmpty());
        assertEquals(-1, TutorialHistory.rootIndex(stack, PREFS, ROOT::equals, TutorialHistoryTest::plugin));
    }
}
