package integration_tests

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
)

// b10d: the bounds the server puts on what one connection's requests make it
// hold, through the real server and client: the TCP request's address, the
// StreamLimiter's say on a UDP session's new destinations, and the session
// readers that may wait to send to the client (server.MaxBlockedUDPSenders).

func eventually(d time.Duration, f func() bool) bool {
	for deadline := time.Now().Add(d); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if f() {
			return true
		}
	}
	return f()
}

// recordingLimiter admits everything but the destinations refuse names, each
// only the first time it is asked, and records what it is asked.
type recordingLimiter struct {
	mu     sync.Mutex
	tcp    []string
	dests  []string
	refuse map[string]bool
}

func (l *recordingLimiter) AllowTCP(_, reqAddr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tcp = append(l.tcp, reqAddr)
	return true
}

func (l *recordingLimiter) AllowUDP(string, string) bool { return true }

func (l *recordingLimiter) AllowUDPDest(_, reqAddr string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dests = append(l.dests, reqAddr)
	if l.refuse[reqAddr] {
		delete(l.refuse, reqAddr)
		return false
	}
	return true
}

func (l *recordingLimiter) asked() (tcp, dests []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.tcp...), append([]string(nil), l.dests...)
}

// recordingOutbound answers TCP with an in-memory echo and gives each UDP
// session a socket that keeps the addresses it is sent to and never answers.
type recordingOutbound struct {
	mu      sync.Mutex
	dials   []string
	written []string
}

func (o *recordingOutbound) TCP(reqAddr string) (net.Conn, error) {
	o.mu.Lock()
	o.dials = append(o.dials, reqAddr)
	o.mu.Unlock()
	a, b := net.Pipe()
	go func() {
		_, _ = io.Copy(b, b)
		_ = b.Close()
	}()
	return a, nil
}

func (o *recordingOutbound) UDP(string) (server.UDPConn, error) {
	return &recordingUDPConn{o: o, closed: make(chan struct{})}, nil
}

func (o *recordingOutbound) CheckUDP(string) error { return nil }

func (o *recordingOutbound) seen() (dials, written []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.dials...), append([]string(nil), o.written...)
}

type recordingUDPConn struct {
	o      *recordingOutbound
	once   sync.Once
	closed chan struct{}
}

func (c *recordingUDPConn) ReadFrom([]byte) (int, string, error) {
	<-c.closed
	return 0, "", net.ErrClosed
}

func (c *recordingUDPConn) WriteTo(b []byte, addr string) (int, error) {
	c.o.mu.Lock()
	c.o.written = append(c.o.written, addr)
	c.o.mu.Unlock()
	return len(b), nil
}

func (c *recordingUDPConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func startBoundsServer(t *testing.T, cfg *server.Config) client.Client {
	t.Helper()
	udpConn, udpAddr, err := serverConn()
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSConfig = serverTLSConfig()
	cfg.Conn = udpConn
	cfg.Authenticator = authAll{}
	s, err := server.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() { _ = s.Close() })
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// TestTCPRequestAddressCap (b10d): a stream naming an address longer than any
// host:port is closed before the limiter, the hook or the outbound sees it,
// and the connection goes on; the longest real address is dialled.
func TestTCPRequestAddressCap(t *testing.T) {
	limiter := &recordingLimiter{}
	ob := &recordingOutbound{}
	c := startBoundsServer(t, &server.Config{Outbound: ob, StreamLimiter: limiter})
	longest := strings.Repeat("a", 254) + ":65535"
	if conn, err := c.TCP(longest + "0"); err == nil {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, err = conn.Read(make([]byte, 1))
		assert.Error(t, err, "a stream to an over-long address was kept")
		_ = conn.Close()
	}
	conn, err := c.TCP(longest)
	if err != nil {
		t.Fatalf("the longest real address was refused: %v", err)
	}
	defer conn.Close()
	_, err = conn.Write([]byte("ping"))
	assert.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	assert.NoError(t, err)
	tcp, _ := limiter.asked()
	dials, _ := ob.seen()
	if len(tcp) != 1 || tcp[0] != longest || len(dials) != 1 || dials[0] != longest {
		t.Fatalf("AllowTCP asked about %d addresses, the outbound dialled %d; want only the longest real one each", len(tcp), len(dials))
	}
}

// TestStreamLimiterAllowUDPDest (b10d): the limiter is asked about each new
// destination of a UDP session, its first excepted; a refusal drops that
// datagram and is asked again on the next one there, a pass is remembered.
func TestStreamLimiterAllowUDPDest(t *testing.T) {
	limiter := &recordingLimiter{refuse: map[string]bool{"192.0.2.2:9": true}}
	ob := &recordingOutbound{}
	c := startBoundsServer(t, &server.Config{Outbound: ob, StreamLimiter: limiter})
	u, err := c.UDP()
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	// Each datagram waits for the one before it to land: datagrams may not
	// arrive in the order sent.
	steps := []struct {
		to             string
		asked, written int
	}{
		{"192.0.2.1:9", 0, 1}, // the session's first: AllowUDP covered it
		{"192.0.2.2:9", 1, 1}, // refused: dropped
		{"192.0.2.2:9", 2, 2}, // asked again, passes
		{"192.0.2.2:9", 2, 3}, // remembered
		{"192.0.2.3:9", 3, 4},
	}
	for i, s := range steps {
		assert.NoError(t, u.Send([]byte(fmt.Sprint(i)), s.to))
		if !eventually(2*time.Second, func() bool {
			_, dests := limiter.asked()
			_, written := ob.seen()
			return len(dests) == s.asked && len(written) == s.written
		}) {
			_, dests := limiter.asked()
			_, written := ob.seen()
			t.Fatalf("datagram %d to %s: asked about %v, written to %v; want %d asks and %d writes", i, s.to, dests, written, s.asked, s.written)
		}
	}
}

// gatedTrafficLogger holds every download LogTraffic while the gate is closed,
// as a capped peer's rate does, and counts the calls waiting at once.
type gatedTrafficLogger struct {
	mu      sync.Mutex
	cond    *sync.Cond
	closed  bool
	waiting atomic.Int64
	peak    atomic.Int64
	calls   atomic.Int64
}

func newGatedTrafficLogger() *gatedTrafficLogger {
	g := &gatedTrafficLogger{closed: true}
	g.cond = sync.NewCond(&g.mu)
	return g
}

func (g *gatedTrafficLogger) LogTraffic(_ string, _, rx uint64) bool {
	if rx == 0 {
		return true
	}
	g.calls.Add(1)
	n := g.waiting.Add(1)
	for p := g.peak.Load(); n > p && !g.peak.CompareAndSwap(p, n); p = g.peak.Load() {
	}
	g.mu.Lock()
	for g.closed {
		g.cond.Wait()
	}
	g.mu.Unlock()
	g.waiting.Add(-1)
	return true
}

func (g *gatedTrafficLogger) open() {
	g.mu.Lock()
	g.closed = false
	g.mu.Unlock()
	g.cond.Broadcast()
}

func (g *gatedTrafficLogger) LogOnlineState(string, bool)                      {}
func (g *gatedTrafficLogger) TraceStream(server.HyStream, *server.StreamStats) {}
func (g *gatedTrafficLogger) UntraceStream(server.HyStream)                    {}

// chattyOutbound gives each UDP session a socket that has a datagram for its
// reader every millisecond until stop, and counts each socket's reads.
type chattyOutbound struct {
	mu    sync.Mutex
	conns []*chattyUDPConn
	stop  chan struct{}
}

func (o *chattyOutbound) TCP(string) (net.Conn, error) { return nil, errors.New("no tcp") }
func (o *chattyOutbound) CheckUDP(string) error        { return nil }

func (o *chattyOutbound) UDP(string) (server.UDPConn, error) {
	c := &chattyUDPConn{stop: o.stop, closed: make(chan struct{})}
	o.mu.Lock()
	o.conns = append(o.conns, c)
	o.mu.Unlock()
	return c, nil
}

// reads snapshots each socket's reads so far.
func (o *chattyOutbound) reads() []int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make([]int64, len(o.conns))
	for i, c := range o.conns {
		out[i] = c.reads.Load()
	}
	return out
}

type chattyUDPConn struct {
	reads  atomic.Int64
	stop   chan struct{}
	once   sync.Once
	closed chan struct{}
}

func (c *chattyUDPConn) ReadFrom(b []byte) (int, string, error) {
	select {
	case <-c.stop:
		<-c.closed
		return 0, "", net.ErrClosed
	case <-c.closed:
		return 0, "", net.ErrClosed
	case <-time.After(time.Millisecond):
	}
	c.reads.Add(1)
	return copy(b, "reply"), "192.0.2.1:9", nil
}

func (c *chattyUDPConn) WriteTo(b []byte, _ string) (int, error) { return len(b), nil }

func (c *chattyUDPConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// TestMaxBlockedUDPSenders (b10d): while a connection's sends to the client
// wait (here on its TrafficLogger, as on a capped peer's rate or a full
// DATAGRAM queue), at most server.MaxBlockedUDPSenders of its sessions wait
// with them; the other sessions' datagrams are dropped before the
// TrafficLogger, uncharged, and their readers go on draining their sockets.
// Once the sends move again, the waiting ones go out.
func TestMaxBlockedUDPSenders(t *testing.T) {
	const sessions = server.MaxBlockedUDPSenders + 36
	gate := newGatedTrafficLogger()
	ob := &chattyOutbound{stop: make(chan struct{})}
	c := startBoundsServer(t, &server.Config{Outbound: ob, TrafficLogger: gate})
	defer gate.open()
	for i := 0; i < sessions; i++ {
		u, err := c.UDP()
		if err != nil {
			t.Fatal(err)
		}
		defer u.Close()
		assert.NoError(t, u.Send([]byte("go"), "192.0.2.1:9"))
	}
	if !eventually(5*time.Second, func() bool { return len(ob.reads()) == sessions && gate.waiting.Load() == server.MaxBlockedUDPSenders }) {
		t.Fatalf("%d sessions opened, %d sends waiting; want %d and %d", len(ob.reads()), gate.waiting.Load(), sessions, server.MaxBlockedUDPSenders)
	}
	before := ob.reads()
	time.Sleep(300 * time.Millisecond)
	after := ob.reads()
	draining, stuck := 0, 0
	for i := range before {
		switch {
		case after[i] > before[i]:
			draining++
		case after[i] == 1:
			stuck++
		}
	}
	if peak, calls := gate.peak.Load(), gate.calls.Load(); peak != server.MaxBlockedUDPSenders || calls != server.MaxBlockedUDPSenders {
		t.Fatalf("%d sends waited at once, %d reached the TrafficLogger; want %d each", peak, calls, server.MaxBlockedUDPSenders)
	}
	if draining != sessions-server.MaxBlockedUDPSenders || stuck != server.MaxBlockedUDPSenders {
		t.Fatalf("%d readers went on reading and %d stayed at their first datagram; want %d and %d", draining, stuck, sessions-server.MaxBlockedUDPSenders, server.MaxBlockedUDPSenders)
	}
	close(ob.stop)
	gate.open()
	if !eventually(5*time.Second, func() bool { return gate.waiting.Load() == 0 }) {
		t.Fatalf("%d sends still waiting after the gate opened", gate.waiting.Load())
	}
}
