package vless

import (
	"net"
	"net/netip"
	"reflect"
	"sync"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

// Verified peers belong to a single outbound instance. They are never persisted.
type verifiedRealityPeers struct {
	mu         sync.Mutex
	dial       uint64
	latestDial uint64
	latest     netip.AddrPort
	watchers   map[chan netip.AddrPort]peerSubscription
	closed     bool
}

type peerSubscription struct {
	after     uint64
	delivered netip.AddrPort
}

func newVerifiedRealityPeers(o option.VLESSOutboundOptions) *verifiedRealityPeers {
	tls := o.TLS
	if !o.ServerIsDomain() || tls == nil || !tls.Enabled || tls.ServerName == "" ||
		tls.UTLS == nil || !tls.UTLS.Enabled || tls.Reality == nil || !tls.Reality.Enabled {
		return nil
	}
	// A detour, V2Ray transport or custom dialer can change what RemoteAddr
	// represents. Only attest the reviewed raw TCP/Reality configuration.
	allowedTLS := option.OutboundTLSOptions{
		Enabled: true, ServerName: tls.ServerName,
		UTLS:    &option.OutboundUTLSOptions{Enabled: true, Fingerprint: tls.UTLS.Fingerprint},
		Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: tls.Reality.PublicKey, ShortID: tls.Reality.ShortID, KeyShare: tls.Reality.KeyShare},
	}
	if o.Transport != nil || o.Multiplex != nil || (o.Encryption != "" && o.Encryption != "none") ||
		(o.Flow != "" && o.Flow != "xtls-rprx-vision") ||
		!reflect.DeepEqual(o.DialerOptions, option.DialerOptions{}) || !reflect.DeepEqual(*tls, allowedTLS) {
		return nil
	}
	return &verifiedRealityPeers{watchers: make(map[chan netip.AddrPort]peerSubscription)}
}

// WatchVerifiedRealityPeer observes the physical TCP peer after an ordinary
// VLESS stream delivers its first payload over authenticated Reality. This
// method does no I/O. With replay=false, only dials begun after subscribing
// qualify. With replay=true, the most recently proved address is also sent.
// The buffered channel coalesces updates. Cancel is idempotent; events already
// queued can still be read after cancellation. A closed channel ends the watch.
func (h *Outbound) WatchVerifiedRealityPeer(replay bool) (<-chan netip.AddrPort, func()) {
	updates := make(chan netip.AddrPort, 1)
	s := h.verifiedPeers
	if s == nil {
		close(updates)
		return updates, func() {}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		close(updates)
		return updates, func() {}
	}
	sub := peerSubscription{}
	if !replay {
		sub.after = s.dial
	} else if s.latest.IsValid() {
		updates <- s.latest
		sub.delivered = s.latest
	}
	s.watchers[updates] = sub
	return updates, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if _, ok := s.watchers[updates]; ok {
			delete(s.watchers, updates)
			close(updates)
		}
	}
}

func (s *verifiedRealityPeers) close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.latest = netip.AddrPort{}
	for updates := range s.watchers {
		delete(s.watchers, updates)
		close(updates)
	}
	return nil
}

type realityPeerDial struct {
	peers  *verifiedRealityPeers
	serial uint64
	peer   netip.AddrPort
}

func (s *verifiedRealityPeers) begin(network string) realityPeerDial {
	if s == nil || N.NetworkName(network) != N.NetworkTCP {
		return realityPeerDial{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return realityPeerDial{}
	}
	s.dial++
	return realityPeerDial{peers: s, serial: s.dial}
}

func (d *realityPeerDial) capture(raw net.Conn, port uint16) {
	if d.peers == nil {
		return
	}
	tcp, ok := raw.RemoteAddr().(*net.TCPAddr)
	if !ok || tcp == nil {
		return
	}
	remote := tcp.AddrPort()
	address := remote.Addr().Unmap()
	if remote.Port() == port && port != 0 && address.IsValid() && address.Zone() == "" &&
		!address.IsUnspecified() && !address.IsMulticast() && !address.IsLinkLocalUnicast() {
		d.peer = netip.AddrPortFrom(address, port)
	}
}

func (d realityPeerDial) observe(conn net.Conn, err error) (net.Conn, error) {
	if err != nil || !d.peer.IsValid() {
		return conn, err
	}
	// Forward counters through the router's optimized Copy/Unwrap paths as well
	// as Read and ReadBuffer. They count the decoded VLESS payload, never the
	// outer TLS handshake, an attempted write, or a rejected VLESS response.
	var first sync.Once
	return bufio.NewCounterConn(conn, []N.CountFunc{func(n int64) {
		if n > 0 {
			first.Do(func() { d.peers.publish(d.serial, d.peer) })
		}
	}}, nil), nil
}

func (s *verifiedRealityPeers) publish(dial uint64, peer netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || dial < s.latestDial {
		return
	}
	s.latestDial, s.latest = dial, peer
	for updates, sub := range s.watchers {
		if dial <= sub.after || sub.delivered == peer {
			continue
		}
		// Only publishers holding mu can write to this channel. Drop an older
		// queued address if the observer hasn't consumed it yet.
		select {
		case <-updates:
		default:
		}
		updates <- peer
		sub.delivered = peer
		s.watchers[updates] = sub
	}
}
