package com.extera.plugins.exitfy;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class CorePreparationGateTest {
    @Test
    public void coalescesDuplicatesAndRejectsStaleServerResults() {
        CorePreparationGate gate = new CorePreparationGate();
        CorePreparationGate.Request first =
                gate.request(CoreFamily.SING_BOX, "server-a");
        CorePreparationGate.Request duplicate =
                gate.request(CoreFamily.SING_BOX, "server-a");
        assertSame(first, duplicate);
        assertTrue(gate.isCurrent(first));

        CorePreparationGate.Request changed =
                gate.request(CoreFamily.XRAY, "server-b");
        assertFalse(gate.isCurrent(first));
        assertTrue(gate.isCurrent(changed));

        gate.cancel();
        assertFalse(gate.isCurrent(changed));
    }
}
