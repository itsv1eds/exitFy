package com.extera.plugins.exitfy;

import org.junit.Test;
import static org.junit.Assert.*;

public class TutorialFlowTest {
    @Test public void firstSetupWaitsForComponentsBeforeOpeningSource() {
        TutorialFlow flow = new TutorialFlow(false);
        assertEquals(TutorialFlow.Step.INSTALL, flow.step());
        assertFalse(flow.advance(TutorialFlow.Step.INSTALL, false));
        assertFalse(flow.advance(TutorialFlow.Step.SOURCE, true));
        assertEquals(0, flow.position());
        assertTrue(flow.advance(TutorialFlow.Step.INSTALL, true));
        assertEquals(TutorialFlow.Step.SOURCE, flow.step());
    }

    @Test public void replayAlwaysStartsWithSourceAndCannotReenterInstallation() {
        TutorialFlow flow = new TutorialFlow(true);
        assertEquals(TutorialFlow.Step.SOURCE, flow.step());
        assertEquals(1, flow.position());
        assertFalse(flow.advance(TutorialFlow.Step.INSTALL, true));
        assertEquals(TutorialFlow.Step.SOURCE, flow.step());
    }

    @Test public void failedActionsAndLateResultsDoNotSkipAnotherStep() {
        TutorialFlow flow = new TutorialFlow(true);
        assertTrue(flow.advance(TutorialFlow.Step.SOURCE, true));
        assertFalse(flow.advance(TutorialFlow.Step.PROVIDER, false));
        assertTrue(flow.advance(TutorialFlow.Step.PROVIDER, true));
        assertFalse(flow.advance(TutorialFlow.Step.SOURCE, true));
        assertFalse(flow.advance(TutorialFlow.Step.REFRESH, false));
        assertEquals(TutorialFlow.Step.REFRESH, flow.step());
        assertTrue(flow.advance(TutorialFlow.Step.REFRESH, true));
        assertFalse(flow.advance(TutorialFlow.Step.SELECT, false));
        assertEquals(TutorialFlow.Step.SELECT, flow.step());
    }

    @Test public void completionMatchesTheActualStepCountAndIsTerminal() {
        TutorialFlow flow = new TutorialFlow(false);
        for (TutorialFlow.Step step : TutorialFlow.Step.values()) {
            if (step == TutorialFlow.Step.DONE) break;
            assertEquals(step, flow.step());
            assertTrue(flow.advance(step, true));
        }
        assertEquals(TutorialFlow.count(), flow.position());
        assertFalse(flow.advance(TutorialFlow.Step.ADVANCED, true));
        flow.finish();
        assertEquals(TutorialFlow.count(), flow.position());
    }
}
