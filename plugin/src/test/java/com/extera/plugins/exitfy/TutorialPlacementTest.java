package com.extera.plugins.exitfy;

import org.junit.Test;
import static org.junit.Assert.*;

public class TutorialPlacementTest {
    @Test public void sourceHintFitsAboveTheTargetWithoutCoveringIt() {
        int budget = TutorialPlacement.availableHeight(510, 580, 24, 760, 10, 12);
        int height = Math.min(240, budget);
        int y = TutorialPlacement.cardTop(510, 580, 24, 760, height, 10, 12);
        assertTrue(y >= 36);
        assertTrue(y + height <= 500);
    }

    @Test public void topButtonPlacesCardBelowItInLandscape() {
        int budget = TutorialPlacement.availableHeight(70, 118, 24, 336, 10, 12);
        int height = Math.min(220, budget);
        int y = TutorialPlacement.cardTop(70, 118, 24, 336, height, 10, 12);
        assertEquals(128, y);
        assertTrue(y + height <= 324);
    }

    @Test public void largeTextIsLimitedToSpaceAboveOrBelowTheTarget() {
        int budget = TutorialPlacement.availableHeight(280, 350, 24, 600, 10, 12);
        int y = TutorialPlacement.cardTop(280, 350, 24, 600, budget, 10, 12);
        assertTrue(y >= 36);
        assertTrue(y + budget <= 270 || y >= 360);
        assertTrue(y + budget <= 588);
    }
}
