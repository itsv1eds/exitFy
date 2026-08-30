package com.extera.plugins.exitfy;

/**
 * The address ranges Telegram hands out as call reflectors.
 *
 * <p>Only these are ever forwarded. The relay listens on loopback, and without
 * this check anything on the device that found the port could have its traffic
 * carried out through the user's server.</p>
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

    static boolean isReflector(String address) {
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
