package integration_tests

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
)

// fragCountingLogger records every LogTraffic charge and approves it.
type fragCountingLogger struct {
	mu     sync.Mutex
	tx, rx uint64
	rxs    []uint64
}

func (l *fragCountingLogger) LogTraffic(_ string, tx, rx uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tx += tx
	l.rx += rx
	if rx > 0 {
		l.rxs = append(l.rxs, rx)
	}
	return true
}
func (l *fragCountingLogger) LogOnlineState(string, bool)                      {}
func (l *fragCountingLogger) TraceStream(server.HyStream, *server.StreamStats) {}
func (l *fragCountingLogger) UntraceStream(server.HyStream)                    {}

// replyOutbound answers each datagram a UDP session sends with one datagram
// of size bytes.
type replyOutbound struct{ size int }

func (replyOutbound) TCP(string) (net.Conn, error) { return nil, errors.New("no tcp") }
func (replyOutbound) CheckUDP(string) error        { return nil }
func (o replyOutbound) UDP(string) (server.UDPConn, error) {
	return &replyConn{size: o.size, in: make(chan string, 4), done: make(chan struct{})}, nil
}

type replyConn struct {
	size int
	in   chan string
	once sync.Once
	done chan struct{}
}

func (c *replyConn) WriteTo(b []byte, addr string) (int, error) {
	select {
	case c.in <- addr:
	default:
	}
	return len(b), nil
}

func (c *replyConn) ReadFrom(b []byte) (int, string, error) {
	select {
	case addr := <-c.in:
		for i := range c.size {
			b[i] = byte(i)
		}
		return c.size, addr, nil
	case <-c.done:
		return 0, "", net.ErrClosed
	}
}

func (c *replyConn) Close() error { c.once.Do(func() { close(c.done) }); return nil }

type authAll struct{}

func (authAll) Authenticate(net.Addr, string, uint64) (bool, string) { return true, "nobody" }

// TestTrafficLoggerChargesADownlinkDatagramOnce (b10d): a downlink datagram
// too big for one QUIC datagram goes out as fragments, and the TrafficLogger,
// which a rate cap sits behind, is charged its size once, as uplink is. The
// sums are asserted, not the calls: fragment sizes follow the path MTU.
func TestTrafficLoggerChargesADownlinkDatagramOnce(t *testing.T) {
	// 4000 B, not 4096: the server reads a reply into a 4096 B buffer and
	// drops what does not fit with the message header (udp.go receiveLoop).
	for _, size := range []int{1000, 3000, 4000} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			udpConn, udpAddr, err := serverConn()
			if err != nil {
				t.Fatal(err)
			}
			tl := &fragCountingLogger{}
			s, err := server.NewServer(&server.Config{
				TLSConfig:     serverTLSConfig(),
				Conn:          udpConn,
				Outbound:      replyOutbound{size: size},
				Authenticator: authAll{},
				TrafficLogger: tl,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			go s.Serve()
			c, _, err := client.NewClient(&client.Config{
				ServerAddr: udpAddr,
				TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
			})
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			conn, err := c.UDP()
			if err != nil {
				t.Fatal(err)
			}
			assert.NoError(t, conn.Send([]byte("ping"), "example.com:53"))
			got := make(chan int, 1)
			go func() {
				bs, _, err := conn.Receive()
				if err != nil {
					got <- -1
					return
				}
				got <- len(bs)
			}()
			select {
			case n := <-got:
				assert.Equal(t, size, n)
			case <-time.After(5 * time.Second):
				t.Fatalf("%d B: no reply", size)
			}
			tl.mu.Lock()
			rx, rxs, tx := tl.rx, append([]uint64(nil), tl.rxs...), tl.tx
			tl.mu.Unlock()
			t.Logf("%d B downlink datagram: charged %v", size, rxs)
			assert.Equal(t, uint64(size), rx, "a %d B downlink datagram charged %v", size, rxs)
			assert.Equal(t, uint64(4), tx)
		})
	}
}
