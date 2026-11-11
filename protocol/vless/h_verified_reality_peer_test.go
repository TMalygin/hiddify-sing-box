//go:build with_utls

package vless

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/sagernet/sing-box/adapter"
	boxtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	protocol "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

const hPeerDomain = "node.peer.invalid"

type hPeerWatcher interface {
	WatchVerifiedRealityPeer(replay bool) (<-chan netip.AddrPort, func())
}

func hWatch(t *testing.T, out *Outbound, replay bool) (<-chan netip.AddrPort, func()) {
	t.Helper()
	watcher, ok := any(out).(hPeerWatcher)
	require.True(t, ok, "a VLESS outbound must support passive observation of its verified physical peer")
	updates, cancel := watcher.WatchVerifiedRealityPeer(replay)
	t.Cleanup(cancel)
	return updates, cancel
}

type hPeerNetwork struct{ adapter.NetworkManager }

func (hPeerNetwork) DefaultOptions() adapter.NetworkOptions   { return adapter.NetworkOptions{} }
func (hPeerNetwork) AutoDetectInterface() bool                { return false }
func (hPeerNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }
func (hPeerNetwork) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}

type hPeerTransports struct{ adapter.DNSTransportManager }

func (hPeerTransports) Transports() []adapter.DNSTransport { return nil }
func (hPeerTransports) Default() adapter.DNSTransport      { return nil }

// A transparent test hop can reach the peer successfully. Its socket is still
// ineligible when a profile explicitly routes the VLESS dial through a detour.
type hPeerHop struct {
	adapter.Outbound
	address netip.AddrPort
}

func (h *hPeerHop) DialContext(ctx context.Context, network string, _ M.Socksaddr) (net.Conn, error) {
	return new(net.Dialer).DialContext(ctx, network, h.address.String())
}

type hPeerHops struct {
	adapter.OutboundManager
	hop *hPeerHop
}

func (h hPeerHops) Outbound(tag string) (adapter.Outbound, bool) { return h.hop, tag == "intermediate" }

type hPeerDNS struct {
	adapter.DNSRouter
	calls atomic.Int32
}

func (d *hPeerDNS) Lookup(_ context.Context, name string, _ adapter.DNSQueryOptions) ([]netip.Addr, error) {
	d.calls.Add(1)
	if name != hPeerDomain {
		return nil, errors.New("unknown test name")
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

// Echo once at the VLESS destination. The fixture never dials that destination.
type hPeerEcho struct{ N.UDPConnectionHandlerEx }

func (hPeerEcho) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	var request [1]byte
	if _, err := io.ReadFull(conn, request[:]); err == nil {
		_, _ = conn.Write(request[:])
	}
}

type hPeerFixture struct {
	ctx      context.Context
	dns      *hPeerDNS
	address  netip.AddrPort
	options  option.VLESSOutboundOptions
	accepted atomic.Int32
}

func hNewPeerFixture(t *testing.T, flow string, plain bool) *hPeerFixture {
	t.Helper()
	target := httptest.NewUnstartedServer(http.NotFoundHandler())
	target.EnableHTTP2 = true
	target.StartTLS()
	t.Cleanup(target.Close)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	user, err := uuid.NewV4()
	require.NoError(t, err)
	config, err := boxtls.NewRealityServer(context.Background(), log.NewNOPFactory().Logger(), option.InboundTLSOptions{
		Enabled: true, ServerName: "cover.peer.invalid",
		Reality: &option.InboundRealityOptions{Enabled: true, PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()), ShortID: []string{"ab"},
			Handshake: option.InboundRealityHandshakeOptions{ServerOptions: option.ServerOptions{Server: "127.0.0.1", ServerPort: target.Listener.Addr().(*net.TCPAddr).AddrPort().Port()}}},
	})
	require.NoError(t, err)
	t.Cleanup(func() { config.Close() })
	handler := protocol.NewService[int](log.NewNOPFactory().Logger(), hPeerEcho{})
	handler.UpdateUsers([]int{1}, []string{user.String()}, []string{flow})
	f := &hPeerFixture{address: listener.Addr().(*net.TCPAddr).AddrPort(), dns: new(hPeerDNS)}
	f.ctx = service.ContextWith[adapter.NetworkManager](context.Background(), hPeerNetwork{})
	f.ctx = service.ContextWith[adapter.DNSTransportManager](f.ctx, hPeerTransports{})
	f.ctx = service.ContextWith[adapter.DNSRouter](f.ctx, f.dns)
	f.ctx = service.ContextWith[adapter.OutboundManager](f.ctx, hPeerHops{hop: &hPeerHop{address: f.address}})
	f.options = option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: hPeerDomain, ServerPort: f.address.Port()}, UUID: user.String(), Flow: flow,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{TLS: &option.OutboundTLSOptions{
			Enabled: true, ServerName: "cover.peer.invalid", UTLS: &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
			Reality: &option.OutboundRealityOptions{Enabled: true, PublicKey: base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), ShortID: "ab"},
		}},
	}
	go func() {
		for {
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			f.accepted.Add(1)
			go func() {
				defer raw.Close()
				_ = raw.SetDeadline(time.Now().Add(4 * time.Second))
				var conn net.Conn = raw
				var verifyErr error
				if !plain {
					conn, verifyErr = boxtls.ServerHandshake(context.Background(), raw, config)
				}
				if verifyErr == nil {
					_ = handler.NewConnection(context.Background(), conn, M.SocksaddrFromNet(raw.RemoteAddr()), nil)
				}
			}()
		}
	}()
	return f
}

func (f *hPeerFixture) outbound(t *testing.T, options option.VLESSOutboundOptions) *Outbound {
	t.Helper()
	out, err := NewOutbound(f.ctx, nil, log.NewNOPFactory().Logger(), "same-tag", options)
	require.NoError(t, err)
	return out.(*Outbound)
}
func hPeerDial(out *Outbound) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	conn, err := out.DialContext(ctx, "tcp", M.ParseSocksaddr("198.51.100.12:80"))
	if err == nil {
		_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	}
	return conn, err
}
func hPeerWrite(t *testing.T, conn net.Conn) {
	t.Helper()
	_, err := conn.Write([]byte{'p'})
	require.NoError(t, err)
}
func hPeerRead(t *testing.T, conn net.Conn, buffered bool) {
	t.Helper()
	if buffered {
		b := buf.New()
		defer b.Release()
		require.NoError(t, bufio.NewExtendedConn(conn).ReadBuffer(b))
		require.Equal(t, []byte{'p'}, b.Bytes())
	} else {
		var reply [1]byte
		_, err := io.ReadFull(conn, reply[:])
		require.NoError(t, err)
		require.Equal(t, byte('p'), reply[0])
	}
}
func hNoPeer(t *testing.T, ch <-chan netip.AddrPort) {
	t.Helper()
	select {
	case addr, ok := <-ch:
		require.False(t, ok, "unexpected peer %v", addr)
	default:
	}
}
func hReceivePeer(t *testing.T, ch <-chan netip.AddrPort, want netip.AddrPort) {
	t.Helper()
	select {
	case addr, ok := <-ch:
		require.True(t, ok)
		require.Equal(t, want, addr)
	case <-time.After(time.Second):
		t.Fatal("missing verified peer from this outbound")
	}
}

// Independently exercises the positive fixture on the original implementation.
func TestH_RealityPeerFixture(t *testing.T) {
	for _, flow := range []string{"", protocol.FlowVision} {
		t.Run("flow="+flow, func(t *testing.T) {
			f := hNewPeerFixture(t, flow, false)
			conn, err := hPeerDial(f.outbound(t, f.options))
			require.NoError(t, err)
			defer conn.Close()
			hPeerWrite(t, conn)
			hPeerRead(t, conn, false)
			require.EqualValues(t, 1, f.accepted.Load())
		})
	}
}

func TestH_VerifiedRealityPeer(t *testing.T) {
	for _, flow := range []string{"", protocol.FlowVision} {
		t.Run("lifecycle-flow="+flow, func(t *testing.T) {
			f := hNewPeerFixture(t, flow, false)
			out := f.outbound(t, f.options)
			other := f.outbound(t, f.options)
			first, cancel := hWatch(t, out, true)
			unrelated, _ := hWatch(t, other, true)
			hNoPeer(t, first)
			require.Zero(t, f.dns.calls.Load())
			require.Zero(t, f.accepted.Load())
			conn, err := hPeerDial(out)
			require.NoError(t, err)
			defer conn.Close()
			hNoPeer(t, first)                 // verified Reality alone does not demonstrate VLESS user acceptance
			fresh, _ := hWatch(t, out, false) // the current socket predates this subscription
			hPeerWrite(t, conn)
			hNoPeer(t, first)
			hPeerRead(t, conn, flow == "")
			hReceivePeer(t, first, f.address)
			hNoPeer(t, fresh)
			hNoPeer(t, unrelated) // even the same tag and credentials in another instance have no history
			late, unsubscribe := hWatch(t, out, true)
			hReceivePeer(t, late, f.address)
			unsubscribe()
			unsubscribe()
			_, open := <-late
			require.False(t, open)
			next, err := hPeerDial(out)
			require.NoError(t, err)
			defer next.Close()
			hPeerWrite(t, next)
			hPeerRead(t, next, false)
			hReceivePeer(t, fresh, f.address) // a new dial may prove the same IP again
			hNoPeer(t, first)
			cancel()
			_, open = <-first
			require.False(t, open)
			require.EqualValues(t, 2, f.accepted.Load())
			require.EqualValues(t, 2, f.dns.calls.Load())
		})
	}
	for _, which := range []string{"wrong-uuid", "wrong-sni", "wrong-key", "custom-dialer", "detour", "plain-vless"} {
		t.Run(which, func(t *testing.T) {
			f := hNewPeerFixture(t, "", which == "plain-vless")
			o := f.options
			switch which {
			case "wrong-uuid":
				user, err := uuid.NewV4()
				require.NoError(t, err)
				o.UUID = user.String()
			case "wrong-sni":
				o.TLS.ServerName = "wrong.peer.invalid"
			case "wrong-key":
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				require.NoError(t, err)
				o.TLS.Reality.PublicKey = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
			case "detour":
				o.DialerOptions.Detour = "intermediate"
			case "plain-vless":
				o.TLS = nil
			case "custom-dialer":
				o.DialerOptions.DisableTCPKeepAlive = true
			}
			out := f.outbound(t, o)
			updates, _ := hWatch(t, out, true)
			conn, err := hPeerDial(out)
			if which == "custom-dialer" || which == "detour" || which == "plain-vless" {
				require.NoError(t, err)
				defer conn.Close()
				hPeerWrite(t, conn)
				hPeerRead(t, conn, false)
			} else if which == "wrong-uuid" {
				require.NoError(t, err)
				defer conn.Close()
				hPeerWrite(t, conn)
				var reply [1]byte
				_, err = io.ReadFull(conn, reply[:])
				require.Error(t, err)
			} else {
				if conn != nil {
					conn.Close()
				}
				require.Error(t, err)
			}
			hNoPeer(t, updates)
			late, _ := hWatch(t, out, true)
			hNoPeer(t, late)
		})
	}
	t.Run("concurrent-subscribe-unsubscribe", func(t *testing.T) {
		f := hNewPeerFixture(t, "", false)
		out := f.outbound(t, f.options)
		w, ok := any(out).(hPeerWatcher)
		require.True(t, ok)
		begin := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-begin
				for j := 0; j < 64; j++ {
					_, cancel := w.WatchVerifiedRealityPeer(j%2 == 0)
					cancel()
					cancel()
				}
			}()
		}
		conn, err := hPeerDial(out)
		require.NoError(t, err)
		defer conn.Close()
		close(begin)
		hPeerWrite(t, conn)
		hPeerRead(t, conn, false)
		wg.Wait()
		late, _ := hWatch(t, out, true)
		hReceivePeer(t, late, f.address)
		require.EqualValues(t, 1, f.dns.calls.Load())
	})
}
