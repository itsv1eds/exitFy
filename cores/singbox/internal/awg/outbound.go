// SPDX-License-Identifier: GPL-3.0-or-later
package awg

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
)

type Peer struct {
	PublicKey    string          `json:"public_key"`
	PresharedKey string          `json:"preshared_key,omitempty"`
	Endpoint     string          `json:"endpoint"`
	AllowedIPs   []string        `json:"allowed_ips"`
	Keepalive    json.RawMessage `json:"persistent_keepalive_interval,omitempty"`
}

type Options struct {
	Server       string            `json:"server"`
	ServerPort   uint16            `json:"server_port"`
	PrivateKey   string            `json:"private_key"`
	LocalAddress []string          `json:"local_address"`
	DNS          []string          `json:"dns"`
	Peers        []Peer            `json:"peers"`
	AWG          map[string]string `json:"awg,omitempty"`
	MTU          int               `json:"mtu"`
	ListenPort   uint16            `json:"listen_port,omitempty"`
}

func Register(registry *outbound.Registry) { outbound.Register[Options](registry, "amneziawg", New) }

type Outbound struct {
	outbound.Adapter
	mu      sync.Mutex
	dev     *device.Device
	network *netstack.Net
	local   []netip.Addr
	closed  bool
}

func New(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Outbound, error) {
	local, dns, uapi, err := configuration(options)
	if err != nil {
		return nil, err
	}
	tun, network, err := netstack.CreateNetTUN(local, dns, options.MTU)
	if err != nil {
		return nil, errors.New("AWG userspace network could not be created")
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	if err = dev.IpcSet(uapi); err != nil {
		dev.Close()
		// Upstream validation errors can include the offending key or obfuscation material.
		return nil, errors.New("AWG configuration rejected: check keys, peers and obfuscation parameters")
	}
	return &Outbound{Adapter: outbound.NewAdapter("amneziawg", tag, []string{"tcp", "udp"}, nil),
		dev: dev, network: network, local: local}, nil
}

func (o *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return net.ErrClosed
	}
	if err := o.dev.Up(); err != nil {
		return errors.New("AWG UDP transport could not be started")
	}
	return nil
}

func (o *Outbound) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.closed {
		o.closed = true
		o.dev.Close()
	}
	return nil
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return o.network.DialContext(ctx, network, destination.String())
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	remote := destination.Addr
	if !remote.IsValid() {
		hosts, err := o.network.LookupContextHost(ctx, destination.Fqdn)
		if err != nil || len(hosts) == 0 {
			return nil, errors.New("AWG destination DNS lookup failed")
		}
		remote, _ = netip.ParseAddr(hosts[0])
	}
	var local netip.Addr
	for _, address := range o.local {
		if address.Is4() == remote.Is4() {
			local = address
			break
		}
	}
	if !local.IsValid() {
		return nil, errors.New("AWG configuration has no address for this IP family")
	}
	socket, err := o.network.ListenUDPAddrPort(netip.AddrPortFrom(local, 0))
	if err != nil {
		return nil, err
	}
	return &packetConn{PacketConn: socket, network: o.network}, nil
}

type packetConn struct {
	net.PacketConn
	network *netstack.Net
}

func (p *packetConn) WriteTo(data []byte, address net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(address)
	if destination.IsFqdn() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		hosts, err := p.network.LookupContextHost(ctx, destination.Fqdn)
		if err != nil || len(hosts) == 0 {
			return 0, errors.New("AWG destination DNS lookup failed")
		}
		address = &net.UDPAddr{IP: net.ParseIP(hosts[0]), Port: int(destination.Port)}
	}
	return p.PacketConn.WriteTo(data, address)
}

func configuration(o Options) ([]netip.Addr, []netip.Addr, string, error) {
	invalid := func(field string) ([]netip.Addr, []netip.Addr, string, error) {
		return nil, nil, "", fmt.Errorf("invalid AWG %s", field)
	}
	if o.MTU < 576 || o.MTU > 9000 || len(o.LocalAddress) == 0 || len(o.LocalAddress) > 16 || len(o.DNS) > 16 || len(o.Peers) == 0 || len(o.Peers) > 64 {
		return invalid("network limits")
	}
	if err := validateParameters(o.AWG, o.MTU); err != nil {
		return invalid("obfuscation limits")
	}
	private, err := keyHex(o.PrivateKey)
	if err != nil {
		return invalid("private key")
	}
	var local, dns []netip.Addr
	for _, value := range o.LocalAddress {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return invalid("local address")
		}
		if prefix.Addr().IsUnspecified() || prefix.Addr().IsMulticast() {
			return invalid("local address")
		}
		local = append(local, prefix.Addr())
	}
	for _, value := range o.DNS {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return invalid("DNS address")
		}
		dns = append(dns, addr)
	}
	var uapi strings.Builder
	fmt.Fprintf(&uapi, "private_key=%s\nlisten_port=%d\nreplace_peers=true\n", private, o.ListenPort)
	keys := make([]string, 0, len(o.AWG))
	for key := range o.AWG {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		value := o.AWG[key]
		limit := 2048
		if len(key) == 2 && key[0] == 'i' && key[1] >= '1' && key[1] <= '5' {
			limit = 64 * 1024
		}
		if len(value) > limit || strings.ContainsAny(value, "\r\n\x00") || !parameterAllowed(key) {
			return invalid("obfuscation parameter")
		}
		if key == "header_protection_key" {
			value, err = keyHex(value)
			if err != nil {
				return invalid("header protection key")
			}
		}
		fmt.Fprintf(&uapi, "%s=%s\n", key, value)
	}
	seen := make(map[string]bool)
	for _, peer := range o.Peers {
		public, err := keyHex(peer.PublicKey)
		if err != nil || seen[public] {
			return invalid("peer public key")
		}
		seen[public] = true
		host, port, err := net.SplitHostPort(peer.Endpoint)
		if err != nil || host == "" || strings.ContainsAny(host, "\r\n\x00 ") {
			return invalid("peer endpoint")
		}
		number, err := strconv.ParseUint(port, 10, 16)
		if err != nil || number == 0 {
			return invalid("peer endpoint port")
		}
		if len(peer.AllowedIPs) == 0 || len(peer.AllowedIPs) > 256 {
			return invalid("allowed IPs")
		}
		keepalive := "0"
		if len(peer.Keepalive) > 0 {
			keepalive = string(peer.Keepalive)
			if strings.HasPrefix(keepalive, "\"") {
				keepalive, err = strconv.Unquote(keepalive)
				if err != nil {
					return invalid("peer keepalive")
				}
			}
			if _, maximum, ok := unsignedRange(keepalive); !ok || maximum > 65535 {
				return invalid("peer keepalive")
			}
		}
		fmt.Fprintf(&uapi, "public_key=%s\nendpoint=%s\npersistent_keepalive_interval=%s\nreplace_allowed_ips=true\n", public, peer.Endpoint, keepalive)
		if peer.PresharedKey != "" {
			shared, err := keyHex(peer.PresharedKey)
			if err != nil {
				return invalid("peer preshared key")
			}
			fmt.Fprintf(&uapi, "preshared_key=%s\n", shared)
		}
		for _, value := range peer.AllowedIPs {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return invalid("allowed IP")
			}
			fmt.Fprintf(&uapi, "allowed_ip=%s\n", prefix.Masked())
		}
	}
	uapi.WriteByte('\n')
	return local, dns, uapi.String(), nil
}

func keyHex(value string) (string, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(key) != 32 {
		return "", errors.New("invalid key")
	}
	return hex.EncodeToString(key), nil
}

func parameterAllowed(key string) bool {
	switch key {
	case "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5",
		"header_protection_key", "content_padding_addition", "rekey_after_time", "rekey_timeout", "reject_after_time", "keepalive_timeout", "max_handshake_attempts":
		return true
	}
	return false
}
