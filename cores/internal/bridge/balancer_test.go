package bridge

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// Fixtures are emitted by the plugin's BalancerConfigRenderer with synthetic credentials.
func TestGeneratedBalancerRoutesConnectionsAndChoosesFastest(t *testing.T) {
	for _, mode := range []string{"round-robin", "sticky"} {
		t.Run(mode, func(t *testing.T) {
			_ = Stop()
			slow := balancerPeer(t, 'A', 150*time.Millisecond)
			fast := balancerPeer(t, 'B', time.Millisecond)
			value, err := os.ReadFile("../../testdata/balancer-" + mode + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var config map[string]any
			if err = json.Unmarshal(value, &config); err != nil {
				t.Fatal(err)
			}
			port := freePort(t)
			config["inbounds"].([]any)[0].(map[string]any)["port"] = port
			members := config["outbounds"].([]any)
			for i, endpoint := range []net.Listener{slow, fast} {
				members[i].(map[string]any)["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)["port"] = endpoint.Addr().(*net.TCPAddr).Port
			}
			config["burstObservatory"].(map[string]any)["pingConfig"].(map[string]any)["destination"] = "http://probe.invalid/204"
			value, err = json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if err = Start(string(value)); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := Stop(); err != nil {
					t.Error(err)
				}
			}()
			// Both local peers answer the observer's full-path HTTP probe, with different delays.
			time.Sleep(700 * time.Millisecond)
			counts := map[byte]int{}
			for i := 0; i < 8; i++ {
				marker, err := balancerRequest(port)
				if err != nil {
					t.Fatal(err)
				}
				counts[marker]++
			}
			if mode == "round-robin" && (counts['A'] != 4 || counts['B'] != 4) {
				t.Fatalf("round robin distribution: %v", counts)
			}
			if mode == "sticky" && counts['B'] != 8 {
				t.Fatalf("fastest peer was not selected: %v", counts)
			}
		})
	}
}

func balancerPeer(t *testing.T, marker byte, delay time.Duration) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer socket.Close()
				socket.SetDeadline(time.Now().Add(3 * time.Second))
				greeting := make([]byte, 2)
				if _, err := io.ReadFull(socket, greeting); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, socket, int64(greeting[1])); err != nil {
					return
				}
				if _, err := socket.Write([]byte{5, 0}); err != nil {
					return
				}
				header := make([]byte, 4)
				if _, err := io.ReadFull(socket, header); err != nil {
					return
				}
				if err := skipSocksAddress(socket, header[3]); err != nil {
					return
				}
				if _, err := socket.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				first := make([]byte, 4)
				if _, err := io.ReadFull(socket, first); err != nil {
					return
				}
				if bytes.Equal(first, []byte("GET ")) {
					reader := bufio.NewReader(socket)
					for {
						line, err := reader.ReadString('\n')
						if err != nil {
							return
						}
						if line == "\r\n" {
							break
						}
					}
					time.Sleep(delay)
					socket.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				} else if bytes.Equal(first, []byte("TEST")) {
					socket.Write([]byte{marker})
				}
			}()
		}
	}()
	return listener
}

func balancerRequest(port int) (byte, error) {
	socket, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return 0, err
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(3 * time.Second))
	socket.Write([]byte{5, 1, 2})
	response := make([]byte, 2)
	if _, err = io.ReadFull(socket, response); err != nil {
		return 0, err
	}
	if !bytes.Equal(response, []byte{5, 2}) {
		return 0, fmt.Errorf("unexpected SOCKS authentication method")
	}
	auth := append([]byte{1, 9}, []byte("test-user")...)
	auth = append(auth, 9)
	auth = append(auth, []byte("test-pass")...)
	socket.Write(auth)
	if _, err = io.ReadFull(socket, response); err != nil {
		return 0, err
	}
	if !bytes.Equal(response, []byte{1, 0}) {
		return 0, fmt.Errorf("SOCKS authentication rejected")
	}
	host := []byte("target.invalid")
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	request = append(request, 1, 187)
	socket.Write(request)
	header := make([]byte, 4)
	if _, err = io.ReadFull(socket, header); err != nil {
		return 0, err
	}
	if header[1] != 0 {
		return 0, fmt.Errorf("SOCKS request rejected")
	}
	if err = skipSocksAddress(socket, header[3]); err != nil {
		return 0, err
	}
	socket.Write([]byte("TEST"))
	marker := make([]byte, 1)
	_, err = io.ReadFull(socket, marker)
	return marker[0], err
}

func skipSocksAddress(socket net.Conn, kind byte) error {
	count := 0
	switch kind {
	case 1:
		count = 4
	case 4:
		count = 16
	case 3:
		size := make([]byte, 1)
		if _, err := io.ReadFull(socket, size); err != nil {
			return err
		}
		count = int(size[0])
	default:
		return fmt.Errorf("invalid SOCKS address")
	}
	_, err := io.CopyN(io.Discard, socket, int64(count+2))
	return err
}
