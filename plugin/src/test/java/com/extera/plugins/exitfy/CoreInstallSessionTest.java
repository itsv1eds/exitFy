package com.extera.plugins.exitfy;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class CoreInstallSessionTest {
    @Test
    public void coalescesActiveRequestsAndKeepsProgressMonotonic() {
        CoreInstallSession session = new CoreInstallSession();
        CoreInstallSession.Request first = session.request();
        CoreInstallSession.Request duplicate = session.request();

        assertTrue(first.created);
        assertFalse(duplicate.created);
        assertEquals(first.generation, duplicate.generation);
        assertTrue(session.begin(first.generation));
        assertTrue(session.publish(first.generation, 42,
                CoreInstallSession.Stage.DOWNLOADING));
        assertTrue(session.publish(first.generation, 12,
                CoreInstallSession.Stage.VERIFYING));

        CoreInstallSession.Snapshot running = session.snapshot();
        assertEquals(42, running.progress);
        assertEquals(CoreInstallSession.Stage.VERIFYING, running.stage);
        assertTrue(running.active());
    }

    @Test
    public void distinguishesCompletePartialAndFullFailure() {
        CoreInstallSession complete = new CoreInstallSession();
        CoreInstallSession.Request completeRequest = complete.request();
        assertTrue(complete.begin(completeRequest.generation));
        assertTrue(complete.finish(completeRequest.generation, 2));
        assertEquals(CoreInstallSession.State.SUCCESS, complete.snapshot().state);
        assertEquals(CoreInstallSession.Stage.DONE, complete.snapshot().stage);
        assertEquals(100, complete.snapshot().progress);

        CoreInstallSession partial = new CoreInstallSession();
        CoreInstallSession.Request partialRequest = partial.request();
        assertTrue(partial.begin(partialRequest.generation));
        assertTrue(partial.publish(partialRequest.generation, 76,
                CoreInstallSession.Stage.DOWNLOADING));
        assertTrue(partial.finish(partialRequest.generation, 1));
        assertEquals(CoreInstallSession.State.ERROR, partial.snapshot().state);
        assertEquals(CoreInstallSession.Stage.PARTIAL, partial.snapshot().stage);
        assertEquals(76, partial.snapshot().progress);

        CoreInstallSession failed = new CoreInstallSession();
        CoreInstallSession.Request failedRequest = failed.request();
        assertTrue(failed.begin(failedRequest.generation));
        assertTrue(failed.finish(failedRequest.generation, 0));
        assertEquals(CoreInstallSession.Stage.FAILED, failed.snapshot().stage);
    }

    @Test
    public void cancelInvalidatesEveryLateCallback() {
        CoreInstallSession session = new CoreInstallSession();
        CoreInstallSession.Request request = session.request();
        assertTrue(session.begin(request.generation));

        session.cancel();

        assertFalse(session.publish(request.generation, 90,
                CoreInstallSession.Stage.VERIFYING));
        assertFalse(session.finish(request.generation, 2));
        assertEquals(CoreInstallSession.State.IDLE, session.snapshot().state);
        assertFalse(session.snapshot().active());
    }
}
