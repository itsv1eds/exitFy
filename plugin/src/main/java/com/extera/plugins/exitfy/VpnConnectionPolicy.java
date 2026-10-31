package com.extera.plugins.exitfy;

import android.net.ConnectivityManager;
import android.net.NetworkCapabilities;
import org.telegram.messenger.MessagesController;
import java.lang.reflect.Method;

/** Reads system/host policy without changing the client's VPN preferences. */
final class VpnConnectionPolicy {
    private static volatile Method hostDisableGetter;
    private static volatile boolean hostGetterResolved;
    private VpnConnectionPolicy() { }

    static boolean shouldPause(boolean enabled, boolean pauseOnVpn, boolean vpnActive,
                               boolean hostAutoDisabled) {
        return enabled && (hostAutoDisabled || (pauseOnVpn && vpnActive));
    }

    static boolean vpnActive(ConnectivityManager connectivity) {
        return networkState(connectivity).vpn;
    }

    static final class NetworkState {
        final boolean known, vpn, wifi, mobile;

        NetworkState(boolean known, boolean vpn, boolean wifi, boolean mobile) {
            this.known = known;
            this.vpn = vpn;
            this.wifi = wifi;
            this.mobile = mobile;
        }
    }

    static NetworkState networkState(ConnectivityManager connectivity) {
        try {
            NetworkCapabilities caps = connectivity == null ? null
                    : connectivity.getNetworkCapabilities(connectivity.getActiveNetwork());
            if (caps != null) return new NetworkState(true,
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI),
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR));
        } catch (Exception unavailable) { }
        return new NetworkState(false, false, false, false);
    }

    static boolean shouldPauseNetwork(boolean enabled, boolean pauseOnVpn,
                                      NetworkState network, boolean autoDisabled,
                                      int hostMask, boolean alreadyPaused) {
        if (!enabled) return false;
        if (autoDisabled) return true;
        if (!network.known) return alreadyPaused;
        return pauseOnVpn && network.vpn || hostMask >= 0
                && ((hostMask & 1) != 0 && network.vpn
                || (hostMask & 2) != 0 && network.mobile
                || (hostMask & 4) != 0 && network.wifi);
    }

    static int hostDisableMask() {
        try {
            if (!hostGetterResolved) synchronized (VpnConnectionPolicy.class) {
                if (!hostGetterResolved) {
                    try {
                        hostDisableGetter = Class.forName("com.exteragram.messenger.ExteraConfig")
                                .getMethod("getDoNotUseProxy");
                    } catch (ReflectiveOperationException unavailable) { }
                    hostGetterResolved = true;
                }
            }
            Method getter = hostDisableGetter;
            return getter == null ? -1 : ((Number) getter.invoke(null)).intValue();
        } catch (Exception unavailable) { return -1; }
    }

    static boolean hostAutoDisabled() {
        try {
            return MessagesController.getGlobalMainSettings().getBoolean("proxy_auto_disabled_by_vpn", false);
        } catch (Exception unavailable) { return false; }
    }
}
