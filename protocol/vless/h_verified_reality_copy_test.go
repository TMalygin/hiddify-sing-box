//go:build with_utls

package vless

import (
	"bytes"
	"testing"

	"github.com/gofrs/uuid/v5"
	protocol "github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/bufio"
	"github.com/stretchr/testify/require"
)

// The router's stream copy can unwrap both ends and use counters outside the
// net.Conn methods. Its read path must prove exactly the same event as Read.
func TestH_VerifiedRealityPeerRelayCopy(t *testing.T) {
	for _, flow := range []string{"", protocol.FlowVision} {
		t.Run("flow="+flow, func(t *testing.T) {
			fixture := hNewPeerFixture(t, flow, false)
			for _, correctUser := range []bool{true, false} {
				options := fixture.options
				if !correctUser {
					otherUser, err := uuid.NewV4()
					require.NoError(t, err)
					options.UUID = otherUser.String()
				}
				out := fixture.outbound(t, options)
				updates, cancel := hWatch(t, out, true)
				conn, err := hPeerDial(out)
				require.NoError(t, err)
				defer conn.Close()
				written, err := bufio.Copy(conn, bytes.NewBufferString("p"))
				require.NoError(t, err)
				require.EqualValues(t, 1, written)
				hNoPeer(t, updates)
				var response bytes.Buffer
				read, _ := bufio.Copy(&response, conn)
				if correctUser {
					require.EqualValues(t, 1, read)
					require.Equal(t, "p", response.String())
					hReceivePeer(t, updates, fixture.address)
				} else {
					require.Zero(t, read)
					require.Empty(t, response.String())
					hNoPeer(t, updates)
				}
				cancel()
			}
		})
	}
}
