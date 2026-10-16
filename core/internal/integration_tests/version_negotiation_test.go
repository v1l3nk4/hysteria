package integration_tests

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/server"
)

// unknownVersionProbe is a long header of a version no QUIC stack speaks (a
// reserved 0x?a?a?a?a one), padded to the 1200 bytes quic-go needs before it
// answers an unknown version.
func unknownVersionProbe(t *testing.T) []byte {
	t.Helper()
	p := make([]byte, 1200)
	if _, err := rand.Read(p); err != nil {
		t.Fatal(err)
	}
	p[0] = 0xc0 // long header, fixed bit
	binary.BigEndian.PutUint32(p[1:5], 0x1a2a3a4a)
	p[5] = 8  // destination connection ID length
	p[14] = 8 // source connection ID length
	return p
}

// TestDisableVersionNegotiation (b10d): QUICConfig.DisableVersionNegotiation
// reaches the transport. Without it the server answers a long header of an
// unknown version with a Version Negotiation packet, as upstream does; with it
// the server answers nothing. hsd's Salamander listener depends on it to stay
// silent to blind probes (its probe test is the other half of this check).
func TestDisableVersionNegotiation(t *testing.T) {
	for _, disable := range []bool{false, true} {
		addr := startPreAuthServer(t, nil, func(c *server.Config) { c.QUICConfig.DisableVersionNegotiation = disable })
		pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("probe socket: %v", err)
		}
		if _, err := pc.WriteTo(unknownVersionProbe(t), addr); err != nil {
			t.Fatalf("send probe: %v", err)
		}
		_ = pc.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 1500)
		n, _, err := pc.ReadFrom(buf)
		_ = pc.Close()
		vn := err == nil && n >= 5 && buf[0]&0x80 != 0 && binary.BigEndian.Uint32(buf[1:5]) == 0
		switch {
		case disable && err == nil:
			t.Errorf("DisableVersionNegotiation set: the server answered an unknown version (%d bytes, Version Negotiation %v)", n, vn)
		case !disable && !vn:
			t.Errorf("DisableVersionNegotiation unset: no Version Negotiation packet for an unknown version (err %v, %d bytes)", err, n)
		}
	}
}
