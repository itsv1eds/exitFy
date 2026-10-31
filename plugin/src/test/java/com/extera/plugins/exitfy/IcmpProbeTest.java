package com.extera.plugins.exitfy;

import org.junit.Test;
import java.util.Arrays;
import static org.junit.Assert.*;

public class IcmpProbeTest {
    @Test
    public void fullPathChecksCanUseAnInstalledSecondCoreWithoutRestarting() {
        assertEquals("", RuntimePolicy.proxyProbeReadiness(false, true, true, false, false));
        assertEquals("core_missing", RuntimePolicy.proxyProbeReadiness(false, true, false, false, false));
        assertEquals("restart_required", RuntimePolicy.proxyProbeReadiness(false, false, true, false, false));
        assertEquals("restart_required", RuntimePolicy.proxyProbeReadiness(true, true, true, true, false));
        assertEquals("", RuntimePolicy.proxyProbeReadiness(true, false, false, true, true));
    }

    @Test public void ipv4EchoChecksumAndReplyNonceAreValidated() {
        byte[] nonce = new byte[16];
        Arrays.fill(nonce, (byte) 0x35);
        byte[] request = IcmpProbe.request(false, nonce);
        assertEquals(8, request[0]);
        assertEquals(0, IcmpProbe.checksum(request, 0, request.length));
        byte[] reply = request.clone();
        reply[0] = 0;
        reply[4] = 12;
        reply[5] = 34;
        assertTrue(IcmpProbe.matchesReply(false, request, reply, reply.length));
        reply[reply.length - 1] ^= 1;
        assertFalse(IcmpProbe.matchesReply(false, request, reply, reply.length));
        assertFalse(IcmpProbe.matchesReply(false, request, reply, 7));
        reply[reply.length - 1] ^= 1;
        reply[0] = 3;
        assertFalse(IcmpProbe.matchesReply(false, request, reply, reply.length));
    }

    @Test public void ipv6NeedsAnEchoReplyAndMatchingSequence() {
        byte[] request = IcmpProbe.request(true, new byte[16]);
        assertEquals(128, request[0] & 255);
        assertEquals(0, request[2]);
        byte[] reply = request.clone();
        reply[0] = (byte) 129;
        assertTrue(IcmpProbe.matchesReply(true, request, reply, reply.length));
        reply[6] = 1;
        assertFalse(IcmpProbe.matchesReply(true, request, reply, reply.length));
        assertTrue(RuntimePolicy.interruptPingOnCancel("ICMP"));
        assertTrue(RuntimePolicy.replacementNeedsGuardedRestore("ICMP", true));
    }

    @Test public void icmpSelectionSurvivesSettingsAndDashboardRoundTrips() throws Exception {
        SettingsModel settings = SettingsModel.defaults().withSetting("ping_type", "icmp");
        assertEquals("icmp", SettingsModel.fromJson(settings.toJson().toString()).pingType);
        assertEquals("icmp", ExitFyDashboardState.parse("{\"pingType\":\"icmp\"}").pingType);
        assertEquals("tcp", SettingsModel.defaults().pingType);
    }
}
