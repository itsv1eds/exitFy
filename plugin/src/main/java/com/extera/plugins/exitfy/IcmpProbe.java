package com.extera.plugins.exitfy;

import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructTimeval;

import java.io.FileDescriptor;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;

final class IcmpProbe {
    private static final SecureRandom RANDOM = new SecureRandom();

    static Result probe(InetAddress address, long deadline, BooleanSupplier current) {
        if (address == null) return Result.failed("icmp_failed");
        FileDescriptor socket = null;
        boolean ipv6 = address instanceof Inet6Address;
        long started = System.nanoTime();
        try {
            if (!current.getAsBoolean() || Thread.currentThread().isInterrupted()) {
                return Result.failed("cancelled");
            }
            socket = Os.socket(ipv6 ? OsConstants.AF_INET6 : OsConstants.AF_INET,
                    OsConstants.SOCK_DGRAM,
                    ipv6 ? OsConstants.IPPROTO_ICMPV6 : OsConstants.IPPROTO_ICMP);
            Os.connect(socket, address, 0);
            byte[] nonce = new byte[16];
            RANDOM.nextBytes(nonce);
            byte[] request = request(ipv6, nonce);
            long remaining = remainingMillis(deadline);
            if (remaining <= 0L) return Result.failed("icmp_timeout");
            Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_SNDTIMEO,
                    StructTimeval.fromMillis(remaining));
            Os.sendto(socket, request, 0, request.length, 0, address, 0);
            byte[] response = new byte[256];
            while (current.getAsBoolean() && !Thread.currentThread().isInterrupted()
                    && (remaining = remainingMillis(deadline)) > 0L) {
                Os.setsockoptTimeval(socket, OsConstants.SOL_SOCKET, OsConstants.SO_RCVTIMEO,
                        StructTimeval.fromMillis(Math.min(250L, remaining)));
                try {
                    int count = Os.recvfrom(socket, response, 0, response.length, 0,
                            (InetSocketAddress) null);
                    if (matchesReply(ipv6, request, response, count)) {
                        return new Result(true, Math.max(1L,
                                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started)), "ok");
                    }
                } catch (ErrnoException error) {
                    if (error.errno != OsConstants.EAGAIN && error.errno != OsConstants.EINTR) throw error;
                }
            }
            return Result.failed(current.getAsBoolean()
                    && !Thread.currentThread().isInterrupted() ? "icmp_timeout" : "cancelled");
        } catch (ErrnoException error) {
            return Result.failed(error.errno == OsConstants.EPERM
                    || error.errno == OsConstants.EACCES
                    || error.errno == OsConstants.EPROTONOSUPPORT
                    || error.errno == OsConstants.EAFNOSUPPORT
                    ? "icmp_unavailable" : "icmp_failed");
        } catch (Exception error) {
            return Result.failed("icmp_failed");
        } finally {
            if (socket != null) try { Os.close(socket); } catch (Exception ignored) { }
        }
    }

    static byte[] request(boolean ipv6, byte[] nonce) {
        if (nonce == null || nonce.length != 16) throw new IllegalArgumentException("invalid ICMP nonce");
        byte[] packet = new byte[24];
        packet[0] = (byte) (ipv6 ? 128 : 8);
        packet[6] = nonce[0];
        packet[7] = nonce[1];
        System.arraycopy(nonce, 0, packet, 8, nonce.length);
        if (!ipv6) {
            int checksum = checksum(packet, 0, packet.length);
            packet[2] = (byte) (checksum >>> 8);
            packet[3] = (byte) checksum;
        }
        return packet;
    }

    static boolean matchesReply(boolean ipv6, byte[] request, byte[] reply, int count) {
        if (request == null || request.length != 24 || reply == null || count > reply.length || count < 24) return false;
        int offset = 0;
        if (!ipv6 && (reply[0] & 0xf0) == 0x40) {
            offset = (reply[0] & 15) * 4;
            if (offset < 20 || offset + 24 > count || (reply[9] & 255) != 1) return false;
        }
        if (count != offset + request.length || (reply[offset] & 255) != (ipv6 ? 129 : 0)
                || reply[offset + 1] != 0) return false;
        for (int i = 6; i < request.length; i++) if (request[i] != reply[offset + i]) return false;
        return true;
    }

    static int checksum(byte[] bytes, int offset, int count) {
        long sum = 0;
        for (int i = offset; i < offset + count; i += 2) {
            sum += (bytes[i] & 255) << 8;
            if (i + 1 < offset + count) sum += bytes[i + 1] & 255;
        }
        while ((sum >>> 16) != 0) sum = (sum & 0xffff) + (sum >>> 16);
        return (int) (~sum & 0xffff);
    }

    private static long remainingMillis(long deadline) {
        long nanos = deadline - System.nanoTime();
        return nanos <= 0L ? 0L : Math.max(1L, TimeUnit.NANOSECONDS.toMillis(nanos));
    }

    static final class Result {
        final boolean ok;
        final long millis;
        final String status;
        Result(boolean ok, long millis, String status) {
            this.ok = ok;
            this.millis = millis;
            this.status = status;
        }
        static Result failed(String status) { return new Result(false, -1L, status); }
    }
}
