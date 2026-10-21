package com.extera.plugins.exitfy;

import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import org.telegram.messenger.MessagesController;

/** Reads system/host policy without changing the client's VPN preferences. */
final class VpnConnectionPolicy {
    private VpnConnectionPolicy() { }

    static boolean shouldPause(boolean enabled, boolean pauseOnVpn, boolean vpnActive,
                               boolean hostAutoDisabled) {
        return enabled && (hostAutoDisabled || (pauseOnVpn && vpnActive));
    }

    static boolean vpnActive(ConnectivityManager connectivity) {
        try {
            if (connectivity == null) return false;
            NetworkCapabilities caps = connectivity.getNetworkCapabilities(connectivity.getActiveNetwork());
            return caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        } catch (Exception unavailable) { return false; }
    }

    static boolean hostAutoDisabled() {
        try {
            return MessagesController.getGlobalMainSettings().getBoolean("proxy_auto_disabled_by_vpn", false);
        } catch (Exception unavailable) { return false; }
    }
}
