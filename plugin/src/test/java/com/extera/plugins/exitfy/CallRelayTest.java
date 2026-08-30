package com.extera.plugins.exitfy;

import org.junit.Test;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Exercises the forwarder against a SOCKS5 server that behaves like the core:
 * the parts under our control are testable here, and a call failing on a
 * device says nothing about which end is wrong.
 */
public class CallRelayTest {
    private static final String REFLECTOR = "91.108.4.7";
    private static final int REFLECTOR_PORT = 599;

    @Test
    public void aDatagramReachesTheReflectorThroughTheProxyAndComesBack() throws Exception {
        try (FakeSocks socks = new FakeSocks("user", "secret");
             CallRelay relay = new CallRelay("127.0.0.1", socks.port(), "user", "secret");
             DatagramSocket caller = new DatagramSocket(
                     new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))) {
            int local = relay.mapEndpoint(REFLECTOR, REFLECTOR_PORT);
            assertTrue(local > 0);

            byte[] payload = "call-media".getBytes(StandardCharsets.UTF_8);
            caller.send(new DatagramPacket(payload, payload.length,
                    InetAddress.getByName("127.0.0.1"), local));

            byte[] wrapped = socks.awaitDatagram();
            assertNotNull("the proxy never saw the datagram", wrapped);
            // RSV, FRAG, ATYP=IPv4, then the reflector this endpoint stands for.
            assertEquals(0, wrapped[0]);
            assertEquals(0, wrapped[1]);
            assertEquals(0, wrapped[2]);
            assertEquals(1, wrapped[3]);
            assertEquals(91, wrapped[4] & 0xFF);
            assertEquals(108, wrapped[5] & 0xFF);
            assertEquals(4, wrapped[6] & 0xFF);
            assertEquals(7, wrapped[7] & 0xFF);
            assertEquals(REFLECTOR_PORT,
                    ((wrapped[8] & 0xFF) << 8) | (wrapped[9] & 0xFF));
            byte[] body = new byte[wrapped.length - 10];
            System.arraycopy(wrapped, 10, body, 0, body.length);
            assertArrayEquals(payload, body);

            byte[] answer = "reflector-answer".getBytes(StandardCharsets.UTF_8);
            socks.replyToLastSender(REFLECTOR, REFLECTOR_PORT, answer);

            caller.setSoTimeout(3_000);
            byte[] received = new byte[256];
            DatagramPacket back = new DatagramPacket(received, received.length);
            caller.receive(back);
            byte[] exact = new byte[back.getLength()];
            System.arraycopy(received, 0, exact, 0, back.getLength());
            assertArrayEquals(answer, exact);
        }
    }

    @Test
    public void theSamEndpointKeepsItsPortAndOthersAreBounded() throws Exception {
        try (FakeSocks socks = new FakeSocks("", "");
             CallRelay relay = new CallRelay("127.0.0.1", socks.port(), "", "")) {
            int first = relay.mapEndpoint(REFLECTOR, REFLECTOR_PORT);
            assertEquals(first, relay.mapEndpoint(REFLECTOR, REFLECTOR_PORT));

            for (int index = 1; index < CallRelay.MAX_MAPPINGS; index++) {
                relay.mapEndpoint("91.108.4." + (10 + index), REFLECTOR_PORT);
            }
            try {
                relay.mapEndpoint("91.108.4.200", REFLECTOR_PORT);
                fail("an unbounded number of endpoints was accepted");
            } catch (IllegalStateException expected) {
                assertTrue(expected.getMessage().contains("call endpoints"));
            }
        }
    }

    @Test
    public void anythingOutsideTelegramsRangesIsRefused() throws Exception {
        try (FakeSocks socks = new FakeSocks("", "");
             CallRelay relay = new CallRelay("127.0.0.1", socks.port(), "", "")) {
            for (String address : new String[]{"8.8.8.8", "127.0.0.1", "10.0.0.5"}) {
                try {
                    relay.mapEndpoint(address, 443);
                    fail("forwarded a non-reflector address: " + address);
                } catch (IllegalArgumentException expected) {
                    assertTrue(expected.getMessage().contains("reflector"));
                }
            }
            try {
                relay.mapEndpoint(REFLECTOR, 0);
                fail("forwarded an invalid port");
            } catch (IllegalArgumentException expected) {
                assertTrue(expected.getMessage().contains("port"));
            }
        }
    }

    /** Minimal SOCKS5 server: greeting, optional login, UDP associate. */
    private static final class FakeSocks implements Closeable {
        private final ServerSocket listener;
        private final DatagramSocket relay;
        private final Thread acceptor;
        private final AtomicReference<byte[]> lastDatagram = new AtomicReference<>();
        private final AtomicReference<InetSocketAddress> lastSender = new AtomicReference<>();
        private final String username;
        private final String password;
        private volatile boolean running = true;

        FakeSocks(String username, String password) throws IOException {
            this.username = username;
            this.password = password;
            this.listener = new ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"));
            this.relay = new DatagramSocket(
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0));
            this.acceptor = new Thread(this::accept, "fake-socks");
            this.acceptor.setDaemon(true);
            this.acceptor.start();
            Thread reader = new Thread(this::readDatagrams, "fake-socks-udp");
            reader.setDaemon(true);
            reader.start();
        }

        int port() {
            return listener.getLocalPort();
        }

        byte[] awaitDatagram() throws InterruptedException {
            for (int attempt = 0; attempt < 60; attempt++) {
                byte[] value = lastDatagram.get();
                if (value != null) return value;
                Thread.sleep(50L);
            }
            return null;
        }

        void replyToLastSender(String sourceIp, int sourcePort, byte[] body) throws IOException {
            InetSocketAddress sender = lastSender.get();
            if (sender == null) throw new IOException("nothing has been sent yet");
            byte[] frame = new byte[10 + body.length];
            frame[3] = 1;
            String[] parts = sourceIp.split("\\.");
            for (int index = 0; index < 4; index++) {
                frame[4 + index] = (byte) Integer.parseInt(parts[index]);
            }
            frame[8] = (byte) ((sourcePort >> 8) & 0xFF);
            frame[9] = (byte) (sourcePort & 0xFF);
            System.arraycopy(body, 0, frame, 10, body.length);
            relay.send(new DatagramPacket(frame, frame.length, sender));
        }

        private void accept() {
            while (running) {
                try {
                    Socket client = listener.accept();
                    handle(client);
                } catch (Exception ignored) {
                    return;
                }
            }
        }

        private void handle(Socket client) throws IOException {
            InputStream in = client.getInputStream();
            OutputStream out = client.getOutputStream();
            int version = in.read();
            int count = in.read();
            if (version != 5 || count < 1) throw new IOException("bad greeting");
            byte[] methods = new byte[count];
            for (int index = 0; index < count; index++) methods[index] = (byte) in.read();
            boolean wantsLogin = !username.isEmpty();
            out.write(new byte[]{5, (byte) (wantsLogin ? 2 : 0)});
            out.flush();
            if (wantsLogin) {
                in.read();
                byte[] user = new byte[in.read()];
                for (int index = 0; index < user.length; index++) user[index] = (byte) in.read();
                byte[] secret = new byte[in.read()];
                for (int index = 0; index < secret.length; index++) {
                    secret[index] = (byte) in.read();
                }
                boolean ok = username.equals(new String(user, StandardCharsets.UTF_8))
                        && password.equals(new String(secret, StandardCharsets.UTF_8));
                out.write(new byte[]{1, (byte) (ok ? 0 : 1)});
                out.flush();
                if (!ok) throw new IOException("bad login");
            }
            byte[] request = new byte[10];
            for (int index = 0; index < request.length; index++) {
                request[index] = (byte) in.read();
            }
            if (request[1] != 3) throw new IOException("expected UDP associate");
            int bound = relay.getLocalPort();
            out.write(new byte[]{5, 0, 0, 1, 127, 0, 0, 1,
                    (byte) ((bound >> 8) & 0xFF), (byte) (bound & 0xFF)});
            out.flush();
            // The control connection stays open for the association's lifetime.
        }

        private void readDatagrams() {
            byte[] buffer = new byte[4096];
            while (running) {
                try {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    relay.receive(packet);
                    byte[] exact = new byte[packet.getLength()];
                    System.arraycopy(buffer, 0, exact, 0, packet.getLength());
                    lastSender.set(new InetSocketAddress(packet.getAddress(), packet.getPort()));
                    lastDatagram.set(exact);
                } catch (Exception ignored) {
                    return;
                }
            }
        }

        @Override
        public void close() {
            running = false;
            try {
                listener.close();
            } catch (IOException ignored) {
            }
            relay.close();
            acceptor.interrupt();
        }
    }
}
