package awg

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/crypto/curve25519"
)

func keys(t *testing.T) (string, string) {
	t.Helper()
	private := make([]byte, 32)
	if _, err := rand.Read(private); err != nil {
		t.Fatal(err)
	}
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public)
}
func unusedUDP(t *testing.T) int {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	return socket.LocalAddr().(*net.UDPAddr).Port
}
func TestObfuscatedTunnelCarriesTCPAndUDP(t *testing.T) {
	clientKey, clientPublic := keys(t)
	serverKey, serverPublic := keys(t)
	clientPort, serverPort := unusedUDP(t), unusedUDP(t)
	for serverPort == clientPort {
		serverPort = unusedUDP(t)
	}
	params := map[string]string{"jc": "3", "jmin": "32", "jmax": "64", "s1": "24", "s2": "24",
		"h1": "1234567", "h2": "2345678", "h3": "3456789", "h4": "4567890"}
	makeSide := func(private, public, local, remote string, listen, peerPort int) *Outbound {
		raw, err := New(context.Background(), nil, nil, "test", Options{PrivateKey: private, MTU: 1280,
			LocalAddress: []string{local + "/32"}, DNS: []string{}, ListenPort: uint16(listen), AWG: params,
			Peers: []Peer{{PublicKey: public, Endpoint: net.JoinHostPort("127.0.0.1", strconv.Itoa(peerPort)), AllowedIPs: []string{remote + "/32"}}}})
		if err != nil {
			t.Fatal(err)
		}
		side := raw.(*Outbound)
		t.Cleanup(func() { side.Close() })
		if err = side.Start(adapter.StartStateStart); err != nil {
			t.Fatal(err)
		}
		return side
	}
	server := makeSide(serverKey, clientPublic, "10.23.0.1", "10.23.0.2", serverPort, clientPort)
	client := makeSide(clientKey, serverPublic, "10.23.0.2", "10.23.0.1", clientPort, serverPort)
	listener, err := server.network.ListenTCPAddrPort(netip.MustParseAddrPort("10.23.0.1:9090"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		socket, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer socket.Close()
		socket.SetDeadline(time.Now().Add(8 * time.Second))
		_, err = io.CopyN(socket, socket, 4)
		done <- err
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	socket, err := client.DialContext(ctx, "tcp", M.ParseSocksaddr("10.23.0.1:9090"))
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = socket.Write([]byte("AWG!")); err != nil {
		t.Fatal(err)
	}
	received := make([]byte, 4)
	if _, err = io.ReadFull(socket, received); err != nil || string(received) != "AWG!" {
		t.Fatalf("TCP tunnel: %q %v", received, err)
	}
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	receiver, err := server.network.ListenUDPAddrPort(netip.MustParseAddrPort("10.23.0.1:9091"))
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	receiver.SetDeadline(time.Now().Add(8 * time.Second))
	packet, err := client.ListenPacket(ctx, M.ParseSocksaddr("10.23.0.1:9091"))
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	packet.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = packet.WriteTo([]byte("UDP!"), M.ParseSocksaddr("10.23.0.1:9091").UDPAddr()); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 32)
	count, address, err := receiver.ReadFrom(buffer)
	if err != nil || string(buffer[:count]) != "UDP!" {
		t.Fatalf("UDP tunnel: %q %v", buffer[:count], err)
	}
	if _, err = receiver.WriteTo(buffer[:count], address); err != nil {
		t.Fatal(err)
	}
	count, _, err = packet.ReadFrom(buffer)
	if err != nil || string(buffer[:count]) != "UDP!" {
		t.Fatalf("UDP reply: %q %v", buffer[:count], err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestConfigurationRejectsInjectionAndNeverReturnsKeyMaterial(t *testing.T) {
	private, public := keys(t)
	base := Options{PrivateKey: private, MTU: 1280, LocalAddress: []string{"10.0.0.2/32"}, Peers: []Peer{{PublicKey: public, Endpoint: "127.0.0.1:2345", AllowedIPs: []string{"0.0.0.0/0"}}}}
	cases := []Options{base, base, base}
	cases[0].PrivateKey = "secret-private-key"
	cases[1].AWG = map[string]string{"jc": "1\nprivate_key=secret"}
	cases[2].AWG = map[string]string{"postup": "secret-command"}
	for _, value := range cases {
		_, _, _, err := configuration(value)
		if err == nil {
			t.Fatal("invalid configuration accepted")
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), private) {
			t.Fatal("credential escaped error")
		}
	}
}

func TestConfigurationBoundsHandshakeAllocations(t *testing.T) {
	private, public := keys(t)
	for _, parameters := range []map[string]string{
		{"jc": "4294967295"}, {"jc": "3", "jmin": "128", "jmax": "64"},
		{"jc": "128", "jmin": "1", "jmax": "65000"},
		{"i1": "<r -1>"}, {"i1": "<r 999999999>"}, {"i1": "<dz -1>"},
		{"s4": "65000"}, {"content_padding_addition": "0-4294967295"},
	} {
		value := Options{PrivateKey: private, MTU: 1280, LocalAddress: []string{"10.0.0.2/32"}, AWG: parameters,
			Peers: []Peer{{PublicKey: public, Endpoint: "127.0.0.1:2345", AllowedIPs: []string{"0.0.0.0/0"}}}}
		if _, _, _, err := configuration(value); err == nil {
			t.Fatal("unsafe handshake parameters accepted")
		}
	}
	if !validIPacket("<b 0x0102><r 32><rc 8><rd 4><t><dz 2><d><ds>") {
		t.Fatal("valid obfuscation chain rejected")
	}
}

func TestConfigurationPreservesLongSignaturePackets(t *testing.T) {
	private, public := keys(t)
	packet := "<b 0x" + strings.Repeat("ab", 1600) + ">"
	value := Options{PrivateKey: private, MTU: 1280, LocalAddress: []string{"10.0.0.2/32"}, AWG: map[string]string{"i1": packet},
		Peers: []Peer{{PublicKey: public, Endpoint: "127.0.0.1:2345", AllowedIPs: []string{"0.0.0.0/0"}}}}
	_, _, config, err := configuration(value)
	if err != nil || !strings.Contains(config, "i1="+packet+"\n") {
		t.Fatal("long I-packet was rejected or changed")
	}
	value.AWG["i1"] = "<b 0x" + strings.Repeat("ab", 32768) + ">"
	if _, _, _, err = configuration(value); err == nil {
		t.Fatal("oversized I-packet accepted")
	}
}
