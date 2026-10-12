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
        assertEquals(8, flow.totalSteps());
        int displayed = 0;
        for (TutorialFlow.Step step : TutorialFlow.Step.values()) {
            if (step == TutorialFlow.Step.DONE || step == TutorialFlow.Step.SUBSCRIPTION) continue;
            assertEquals(step, flow.step());
            assertEquals(displayed++, flow.displayPosition());
            assertTrue(flow.advance(step, true));
        }
        assertEquals(TutorialFlow.count(), flow.position());
        assertFalse(flow.advance(TutorialFlow.Step.ADVANCED, true));
        flow.finish();
        assertEquals(TutorialFlow.count(), flow.position());
    }

    @Test public void customSourceAddsInputStepAndWaitsForSuccessfulSubmission() {
        TutorialFlow flow = new TutorialFlow(true);
        flow.advance(TutorialFlow.Step.SOURCE, true);
        assertTrue(flow.chooseProvider(true));
        assertEquals(TutorialFlow.Step.SUBSCRIPTION, flow.step());
        assertEquals(9, flow.totalSteps());
        assertEquals(3, flow.displayPosition());
        assertFalse(flow.advance(TutorialFlow.Step.SUBSCRIPTION, false));
        assertFalse(flow.chooseProvider(false));
        assertFalse(flow.advance(TutorialFlow.Step.REFRESH, true));
        assertTrue(flow.advance(TutorialFlow.Step.SUBSCRIPTION, true));
        assertEquals(TutorialFlow.Step.REFRESH, flow.step());
        assertEquals(4, flow.displayPosition());
        while (flow.step() != TutorialFlow.Step.DONE) flow.advance(flow.step(), true);
        assertEquals(flow.totalSteps(), flow.displayPosition());
    }

    @Test public void configuredCustomSourceSkipsDuplicateSubscriptionInput() {
        TutorialFlow flow = new TutorialFlow(true);
        flow.advance(TutorialFlow.Step.SOURCE, true);
        assertTrue(flow.chooseProvider(false));
        assertEquals(TutorialFlow.Step.REFRESH, flow.step());
        assertEquals(8, flow.totalSteps());
        assertEquals(3, flow.displayPosition());
    }
}
