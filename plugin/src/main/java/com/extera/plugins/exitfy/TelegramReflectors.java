package com.extera.plugins.exitfy;

/**
 * Which call endpoints may be forwarded.
 *
 * <p>The relay listens on loopback, so it must not carry traffic for anything
 * on the device that finds the port. It once accepted only a hardcoded list of
 * Telegram's reflector ranges, copied from elsewhere; those ranges change, and
 * an endpoint outside the list was silently refused, which is a whole feature
 * failing over a stale constant.</p>
 *
 * <p>The rule is now what actually matters: a public unicast address. Loopback,
 * private, link-local, multicast and the reserved ends stay refused, so the
 * relay can never be pointed back at the device or its network.</p>
 */
final class TelegramReflectors {
    private static final String[] RANGES = {
            "91.108.4.0/22",
            "91.108.8.0/22",
            "91.108.12.0/22",
            "91.108.16.0/22",
            "91.108.20.0/22",
            "91.108.56.0/22",
            "91.108.58.0/23",
            "91.105.192.0/23",
            "95.161.64.0/20",
            "149.154.160.0/20",
            "185.76.151.0/24",
    };

    private TelegramReflectors() {
    }

    /** True for the ranges Telegram is known to publish, kept for tests. */
    static boolean isKnownReflector(String address) {
        long value = toIpv4(address);
        if (value < 0) return false;
        for (String range : RANGES) {
            int slash = range.indexOf('/');
            long network = toIpv4(range.substring(0, slash));
            int prefix = Integer.parseInt(range.substring(slash + 1));
            long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            if (network >= 0 && (value & mask) == (network & mask)) return true;
        }
        return false;
    }

    /**
     * A public unicast address, which is the only kind a call endpoint can be.
     */
    static boolean isForwardable(String address) {
        long value = toIpv4(address);
        if (value < 0) return false;
        long first = (value >>> 24) & 0xFF;
        long second = (value >>> 16) & 0xFF;
        if (first == 0 || first == 10 || first == 127 || first >= 224) return false;
        if (first == 100 && second >= 64 && second <= 127) return false;
        if (first == 169 && second == 254) return false;
        if (first == 172 && second >= 16 && second <= 31) return false;
        if (first == 192 && second == 168) return false;
        if (first == 192 && second == 0) return false;
        if (first == 198 && (second == 18 || second == 19)) return false;
        return true;
    }

    static long toIpv4(String address) {
        if (address == null) return -1L;
        String value = address.trim();
        if (value.isEmpty() || value.length() > 15) return -1L;
        long result = 0L;
        int start = 0;
        for (int part = 0; part < 4; part++) {
            int end = part == 3 ? value.length() : value.indexOf('.', start);
            if (end <= start || (part < 3 && end < 0)) return -1L;
            if (part == 3 && value.indexOf('.', start) >= 0) return -1L;
            int octet = 0;
            for (int index = start; index < end; index++) {
                char digit = value.charAt(index);
                if (digit < '0' || digit > '9') return -1L;
                octet = octet * 10 + (digit - '0');
                if (octet > 255) return -1L;
            }
            if (end - start > 1 && value.charAt(start) == '0') return -1L;
            result = (result << 8) | octet;
            start = end + 1;
        }
        return result;
    }
}
