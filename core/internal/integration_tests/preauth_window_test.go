package integration_tests

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
)

// These tests cover the b10d hold on the connection receive window while a
// connection keeps its PreAuthLimiter slot: quic-go grows that window when the
// server reads fast, which a client that has not authenticated can make it do
// with frames http3 reads and drops, and then leave that much unread where
// nothing reads it. quic-go tunes the window from the round-trip time, which
// loopback all but lacks, so each side's datagrams go out through a delay.

// The windows of hsd's listeners: Caddy's initial pair, hysteria's maxima.
const (
	windowTestInitialStream = 512 * 1024
	windowTestInitialConn   = 768 * 1024
	windowTestMaxStream     = 8 << 20
	windowTestMaxConn       = 20 << 20
	windowTestOneWay        = 10 * time.Millisecond
)

// delayedPacketConn sends each datagram delay after it was written, in order,
// as a link with that one-way latency would.
type delayedPacketConn struct {
	net.PacketConn
	delay time.Duration
	queue chan delayedPacket
	done  chan struct{}
	once  sync.Once
}

type delayedPacket struct {
	at   time.Time
	b    []byte
	addr net.Addr
}

func newDelayedPacketConn(pc net.PacketConn, delay time.Duration) *delayedPacketConn {
	c := &delayedPacketConn{PacketConn: pc, delay: delay, queue: make(chan delayedPacket, 4096), done: make(chan struct{})}
	go func() {
		for {
			select {
			case p := <-c.queue:
				time.Sleep(time.Until(p.at))
				_, _ = c.PacketConn.WriteTo(p.b, p.addr)
			case <-c.done:
				return
			}
		}
	}()
	return c
}

func (c *delayedPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	p := delayedPacket{at: time.Now().Add(c.delay), b: append([]byte(nil), b...), addr: addr}
	select {
	case c.queue <- p:
		return len(b), nil
	case <-c.done:
		return 0, net.ErrClosed
	}
}

func (c *delayedPacketConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.PacketConn.Close()
}

// delayedUDP is a UDP socket on 127.0.0.1 whose datagrams leave through a
// delay.
func delayedUDP(t *testing.T) *delayedPacketConn {
	t.Helper()
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	pc := newDelayedPacketConn(udp, windowTestOneWay)
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

// windowTestOutbound drains a stream to "sink:1" at once and never reads one
// to "stall:1", whose bytes then wait in the server's receive buffers.
type windowTestOutbound struct{}

func (windowTestOutbound) TCP(reqAddr string) (net.Conn, error) {
	a, b := net.Pipe()
	if reqAddr == "sink:1" {
		go func() { _, _ = io.Copy(io.Discard, b) }()
	}
	return a, nil
}
func (windowTestOutbound) UDP(string) (server.UDPConn, error) { return nil, io.EOF }
func (windowTestOutbound) CheckUDP(string) error              { return nil }

// startWindowServer is a server with hsd's windows behind a delayed socket.
// Its masquerade holds every request until the test ends without reading the
// body, as a response the client holds back would. lim, when non-nil, is its
// PreAuthLimiter.
func startWindowServer(t *testing.T, lim server.PreAuthLimiter) net.Addr {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return startPreAuthServer(t, delayedUDP(t), func(c *server.Config) {
		c.Outbound = windowTestOutbound{}
		c.PreAuthLimiter = lim
		c.MasqHandler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-ctx.Done() })
		c.QUICConfig.InitialStreamReceiveWindow = windowTestInitialStream
		c.QUICConfig.MaxStreamReceiveWindow = windowTestMaxStream
		c.QUICConfig.InitialConnectionReceiveWindow = windowTestInitialConn
		c.QUICConfig.MaxConnectionReceiveWindow = windowTestMaxConn
	})
}

// h3Frame is an HTTP/3 frame of type typ carrying payload.
func h3Frame(typ uint64, payload []byte) []byte {
	b := quicvarint.Append(nil, typ)
	b = quicvarint.Append(b, uint64(len(payload)))
	return append(b, payload...)
}

// h3GetHeaders is the QPACK block of GET https://hs.b10d.test/ from the
// static table alone: no insert count, no base, :method GET, :scheme https,
// :path / and a literal :authority.
func h3GetHeaders() []byte {
	b := []byte{0x00, 0x00, 0xd1, 0xd7, 0xc1, 0x50, byte(len("hs.b10d.test"))}
	return append(b, "hs.b10d.test"...)
}

// fillUntilBlocked writes to every stream at once until none of them takes a
// byte for 600 ms, and returns how much they took together: what the server
// holds unread.
func fillUntilBlocked(streams []interface {
	Write([]byte) (int, error)
	SetWriteDeadline(time.Time) error
}) int64 {
	var total atomic.Int64
	var wg sync.WaitGroup
	chunk := make([]byte, 16<<10)
	for _, s := range streams {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_ = s.SetWriteDeadline(time.Now().Add(600 * time.Millisecond))
				n, err := s.Write(chunk)
				total.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
	}
	wg.Wait()
	return total.Load()
}

// pumpThenFill is a client that never authenticates: it dials addr through a
// delay, pumps the connection window with 16 MiB of unknown frames on its
// control stream, which http3 reads and drops, then opens eight requests whose
// bodies nobody reads and both QPACK streams, which nothing reads, and fills
// them. It returns what the server held unread.
func pumpThenFill(t *testing.T, addr net.Addr) int64 {
	t.Helper()
	tr := &quic.Transport{Conn: delayedUDP(t)}
	t.Cleanup(func() { _ = tr.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "hs.b10d.test"},
		&quic.Config{MaxIdleTimeout: 30 * time.Second, KeepAlivePeriod: time.Second})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })

	ctl, err := conn.OpenUniStream()
	if err != nil {
		t.Fatalf("control stream: %v", err)
	}
	if _, err := ctl.Write(append([]byte{0x00}, h3Frame(0x04, nil)...)); err != nil { // type, SETTINGS
		t.Fatalf("settings: %v", err)
	}
	junk := h3Frame(0x21, make([]byte, 256<<10)) // a reserved type, read and dropped
	for pumped := 0; pumped < 16<<20; pumped += len(junk) {
		if _, err := ctl.Write(junk); err != nil {
			t.Fatalf("pump after %d bytes: %v", pumped, err)
		}
	}

	var streams []interface {
		Write([]byte) (int, error)
		SetWriteDeadline(time.Time) error
	}
	for i := 0; i < 8; i++ {
		octx, ocancel := context.WithTimeout(context.Background(), 2*time.Second)
		st, err := conn.OpenStreamSync(octx)
		ocancel()
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		head := h3Frame(0x01, h3GetHeaders())
		head = append(head, quicvarint.Append(quicvarint.Append(nil, 0x00), 64<<20)...) // DATA, 64 MiB to come
		if _, err := st.Write(head); err != nil {
			t.Fatalf("request %d headers: %v", i, err)
		}
		streams = append(streams, st)
	}
	for _, typ := range []byte{0x02, 0x03} { // QPACK encoder, decoder
		us, err := conn.OpenUniStream()
		if err != nil {
			t.Fatalf("QPACK stream %#x: %v", typ, err)
		}
		if _, err := us.Write([]byte{typ}); err != nil {
			t.Fatalf("QPACK stream %#x: %v", typ, err)
		}
		streams = append(streams, us)
	}
	held := fillUntilBlocked(streams)
	if conn.Context().Err() != nil {
		t.Fatalf("the server closed the connection: %v", context.Cause(conn.Context()))
	}
	return held
}

// TestPreAuthConnectionWindowHeldUntilAuth: a connection holding its
// PreAuthLimiter slot that pumps the connection window with data the server
// reads, then fills eight request bodies and both QPACK streams, which nothing
// reads, leaves at most the initial connection window unread (768 KiB), not
// its streams' windows (5 MiB). Without a limiter the same client gets past
// it, which shows the pump grows the window.
func TestPreAuthConnectionWindowHeldUntilAuth(t *testing.T) {
	t.Run("held", func(t *testing.T) {
		t.Parallel()
		lim := &countingPreAuthLimiter{cap: 4}
		held := pumpThenFill(t, startWindowServer(t, lim))
		t.Logf("an unauthenticated connection that pumped its window left %d KiB unread", held>>10)
		if held > windowTestInitialConn+64<<10 {
			t.Fatalf("an unauthenticated connection left %d KiB unread, past the initial connection window of %d KiB", held>>10, windowTestInitialConn>>10)
		}
		if lim.liveN() != 1 {
			t.Fatalf("the limiter holds %d slots, want the connection's one", lim.liveN())
		}
	})
	t.Run("no limiter", func(t *testing.T) {
		t.Parallel()
		held := pumpThenFill(t, startWindowServer(t, nil))
		t.Logf("with no limiter the same connection left %d KiB unread", held>>10)
		if held < 2*windowTestInitialConn {
			t.Fatalf("with no limiter the pump left only %d KiB unread: it did not grow the window, so the held case shows nothing", held>>10)
		}
	})
}

// TestPreAuthConnectionWindowGrowsAfterAuth: the auth releases the slot and
// with it the window. An authenticated upload moves at the speed it has with
// no limiter at all, and once it has tuned the window up, four streams whose
// target stops reading hold past the initial connection window together.
func TestPreAuthConnectionWindowGrowsAfterAuth(t *testing.T) {
	upload := func(t *testing.T, lim server.PreAuthLimiter) (time.Duration, int64) {
		addr := startWindowServer(t, lim)
		c, _, err := client.NewClient(&client.Config{
			ConnFactory: windowTestConnFactory{t},
			ServerAddr:  addr,
			Auth:        "letmein",
			TLSConfig:   client.TLSConfig{InsecureSkipVerify: true, ServerName: "hs.b10d.test"},
			QUICConfig:  client.QUICConfig{KeepAlivePeriod: 2 * time.Second, MaxIdleTimeout: 30 * time.Second},
		})
		if err != nil {
			t.Fatalf("client: %v", err)
		}
		t.Cleanup(func() { _ = c.Close() })
		sink, err := c.TCP("sink:1")
		if err != nil {
			t.Fatalf("sink stream: %v", err)
		}
		defer sink.Close()
		buf := make([]byte, 64<<10)
		start := time.Now()
		for sent := 0; sent < 24<<20; sent += len(buf) {
			if _, err := sink.Write(buf); err != nil {
				t.Fatalf("upload after %d bytes: %v", sent, err)
			}
		}
		took := time.Since(start)
		var stalled []interface {
			Write([]byte) (int, error)
			SetWriteDeadline(time.Time) error
		}
		for i := 0; i < 4; i++ {
			stall, err := c.TCP("stall:1")
			if err != nil {
				t.Fatalf("stalled stream %d: %v", i, err)
			}
			defer stall.Close()
			stalled = append(stalled, stall)
		}
		return took, fillUntilBlocked(stalled)
	}
	var with, without time.Duration
	var held int64
	t.Run("limiter", func(t *testing.T) {
		lim := &countingPreAuthLimiter{cap: 4}
		with, held = upload(t, lim)
		if lim.liveN() != 0 {
			t.Fatalf("the auth left %d slots held", lim.liveN())
		}
	})
	t.Run("no limiter", func(t *testing.T) {
		without, _ = upload(t, nil)
	})
	t.Logf("24 MiB authenticated upload over a 20 ms round trip: %v with a limiter, %v with none; four stalled streams then held %d KiB", with.Round(time.Millisecond), without.Round(time.Millisecond), held>>10)
	if held < 2*windowTestInitialConn {
		t.Fatalf("after the auth four stalled streams held %d KiB: the connection window stayed near its initial %d KiB", held>>10, windowTestInitialConn>>10)
	}
	if with > without*3/2+200*time.Millisecond {
		t.Fatalf("the authenticated upload took %v with a limiter against %v without: the window did not grow after the auth", with, without)
	}
}

// windowTestConnFactory is a hysteria client's socket through a delay.
type windowTestConnFactory struct{ t *testing.T }

func (f windowTestConnFactory) New(net.Addr) (net.PacketConn, error) { return delayedUDP(f.t), nil }
