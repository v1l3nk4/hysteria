package integration_tests

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"

	"github.com/apernet/hysteria/core/v2/client"
	"github.com/apernet/hysteria/core/v2/server"
)

// These tests cover the b10d pre-auth fields on server.Config (MaxHeaderBytes,
// PreAuthTimeout, PreAuthMaxAge, PreAuthMaxStreams, PreAuthLimiter,
// VerifySourceAddress) and QUICConfig.MaxIncomingUniStreams: each one bounds
// what a connection that has not authenticated may do, with its zero value
// keeping upstream behaviour. The hold on the connection window that a
// PreAuthLimiter slot brings is in preauth_window_test.go.

// preAuthAuthenticator authenticates exactly one password.
type preAuthAuthenticator struct{ password string }

func (a preAuthAuthenticator) Authenticate(_ net.Addr, auth string, _ uint64) (bool, string) {
	if auth == a.password {
		return true, "peer-1"
	}
	return false, ""
}

// preAuthEchoOutbound answers every TCP request with an in-memory echo, so an
// authenticated session can be shown to keep moving data.
type preAuthEchoOutbound struct{}

func (preAuthEchoOutbound) TCP(string) (net.Conn, error) {
	a, b := net.Pipe()
	go func() { _, _ = io.Copy(b, b); _ = b.Close() }()
	return a, nil
}
func (preAuthEchoOutbound) UDP(string) (server.UDPConn, error) { return nil, errors.New("no udp") }
func (preAuthEchoOutbound) CheckUDP(string) error              { return nil }

// startPreAuthServer builds a server on 127.0.0.1:0 with the b10d pre-auth
// fields applied by mutate, and returns its address. conn, when non-nil,
// replaces the listening packet conn (for the handshake-stall test).
func startPreAuthServer(t *testing.T, conn net.PacketConn, mutate func(*server.Config)) net.Addr {
	t.Helper()
	if conn == nil {
		udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		conn = udp
	}
	cfg := &server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          conn,
		Outbound:      preAuthEchoOutbound{},
		Authenticator: preAuthAuthenticator{password: "letmein"},
	}
	if mutate != nil {
		mutate(cfg)
	}
	s, err := server.NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	go s.Serve()
	return conn.LocalAddr()
}

// preAuthDial completes the QUIC+h3 handshake but sends no auth request, so the
// returned connection is unauthenticated. alpn overrides the ALPN (an unknown
// one fails the TLS handshake, modelling a connection that never completes).
func preAuthDial(t *testing.T, addr net.Addr, keepAlive time.Duration, alpn ...string) (*quic.Transport, *quic.Conn, error) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	tr := &quic.Transport{Conn: pc}
	t.Cleanup(func() { _ = tr.Close(); _ = pc.Close() })
	if len(alpn) == 0 {
		alpn = []string{"h3"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := tr.Dial(ctx, addr, &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         alpn,
		ServerName:         "hs.b10d.test",
	}, &quic.Config{KeepAlivePeriod: keepAlive, MaxIdleTimeout: 30 * time.Second, EnableDatagrams: true})
	return tr, conn, err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// preAuthClosedIdle waits for conn to end and fails unless the server closed
// it with H3_NO_ERROR, as an idle close.
func preAuthClosedIdle(t *testing.T, conn *quic.Conn, within time.Duration) {
	t.Helper()
	select {
	case <-conn.Context().Done():
	case <-time.After(within):
		t.Fatalf("the unauthenticated connection was still up after %v", within)
	}
	var appErr *quic.ApplicationError
	if err := context.Cause(conn.Context()); !errors.As(err, &appErr) || !appErr.Remote || appErr.ErrorCode != 0x100 {
		t.Fatalf("the connection ended with %v, want the server's H3_NO_ERROR", err)
	}
}

// preAuthGet sends GET / over conn as a masquerade prober would and reads the
// whole answer.
func preAuthGet(cc *http3.ClientConn) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, "https://hs.b10d.test/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := cc.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// TestPreAuthMaxHeaderBytesRejectsOversize: with MaxHeaderBytes set, a request
// whose HEADERS frame exceeds it gets a stock 431 before any handler runs,
// while a normal request still reaches the masquerade handler (404 here). This
// is the whole bound: http3 otherwise allocates the client-declared length.
func TestPreAuthMaxHeaderBytesRejectsOversize(t *testing.T) {
	addr := startPreAuthServer(t, nil, func(c *server.Config) { c.MaxHeaderBytes = 16 * 1024 })
	rt := &http3.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "hs.b10d.test"}}
	defer rt.Close()
	req := func(headerLen int) (*http.Response, error) {
		r := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "https", Host: addr.String(), Path: "/"}, Header: make(http.Header)}
		if headerLen > 0 {
			r.Header.Set("X-Pad", strings.Repeat("a", headerLen))
		}
		return rt.RoundTrip(r)
	}
	resp, err := req(64 * 1024)
	if err != nil {
		t.Fatalf("oversize request: %v", err)
	}
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("oversize header status = %d, want 431", resp.StatusCode)
	}
	resp, err = req(0)
	if err != nil {
		t.Fatalf("normal request: %v", err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("normal request status = %d, want the masq 404", resp.StatusCode)
	}
}

// TestPreAuthTimeoutClosesIdleConn: an unauthenticated connection kept alive at
// the QUIC layer (periodic PING) is closed once PreAuthTimeout passes with no
// request — which http3.Server.IdleTimeout can't be used for: it would end
// authenticated tunnels too.
func TestPreAuthTimeoutClosesIdleConn(t *testing.T) {
	addr := startPreAuthServer(t, nil, func(c *server.Config) { c.PreAuthTimeout = 1500 * time.Millisecond })
	_, conn, err := preAuthDial(t, addr, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case <-conn.Context().Done():
	case <-time.After(8 * time.Second):
		t.Fatal("unauthenticated connection was not closed by the pre-auth deadline")
	}
}

// TestPreAuthTimeoutWaitsForARequestInFlight: the deadline measures idle time,
// as a keepalive timeout does. A masquerade response streamed over more than
// twice the deadline arrives whole, and the deadline runs again from its end.
func TestPreAuthTimeoutWaitsForARequestInFlight(t *testing.T) {
	const deadline = 600 * time.Millisecond
	const chunks = 8 // one every 200 ms: 1.6 s in flight
	addr := startPreAuthServer(t, nil, func(c *server.Config) {
		c.PreAuthTimeout = deadline
		c.MasqHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			for i := 0; i < chunks; i++ {
				_, _ = w.Write([]byte("0123456789abcdef"))
				w.(http.Flusher).Flush()
				time.Sleep(200 * time.Millisecond)
			}
		})
	})
	_, conn, err := preAuthDial(t, addr, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	body, err := preAuthGet((&http3.Transport{}).NewClientConn(conn))
	if err != nil || len(body) != chunks*16 {
		t.Fatalf("the slow response was cut by the idle deadline: %d of %d bytes, %v", len(body), chunks*16, err)
	}
	served := time.Now()
	preAuthClosedIdle(t, conn, 5*time.Second)
	if idle := time.Since(served); idle < deadline/2 {
		t.Fatalf("closed %v after the response ended, want the full idle deadline %v from there", idle, deadline)
	}
}

// TestPreAuthMaxAgeClosesABusyConn: requests hold off the idle deadline, never
// the max age: a connection sending one every 200 ms is closed at
// PreAuthMaxAge, H3_NO_ERROR, though it is never idle that long.
func TestPreAuthMaxAgeClosesABusyConn(t *testing.T) {
	const maxAge = 1500 * time.Millisecond
	addr := startPreAuthServer(t, nil, func(c *server.Config) {
		c.PreAuthTimeout = 500 * time.Millisecond
		c.PreAuthMaxAge = maxAge
	})
	_, conn, err := preAuthDial(t, addr, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	start := time.Now()
	cc := (&http3.Transport{}).NewClientConn(conn)
	go func() {
		for conn.Context().Err() == nil {
			_, _ = preAuthGet(cc)
			time.Sleep(200 * time.Millisecond)
		}
	}()
	preAuthClosedIdle(t, conn, 5*time.Second)
	if lived := time.Since(start); lived < maxAge*4/5 {
		t.Fatalf("closed after %v of requests every 200 ms, want the max age %v: the idle deadline fired", lived, maxAge)
	}
}

// TestPreAuthTimeoutSparesAuthenticated: a successful auth cancels the deadline
// and the max age, so an authenticated session keeps moving data well past
// both — the trap the masq report flagged for http3.Server.IdleTimeout.
func TestPreAuthTimeoutSparesAuthenticated(t *testing.T) {
	addr := startPreAuthServer(t, nil, func(c *server.Config) {
		c.PreAuthTimeout = time.Second
		c.PreAuthMaxAge = 1500 * time.Millisecond
	})
	c, _, err := client.NewClient(&client.Config{
		ServerAddr: addr,
		Auth:       "letmein",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true, ServerName: "hs.b10d.test"},
		QUICConfig: client.QUICConfig{KeepAlivePeriod: 2 * time.Second, MaxIdleTimeout: 10 * time.Second},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer c.Close()
	time.Sleep(3 * time.Second) // > 2x the pre-auth deadline
	conn, err := c.TCP("echo:1")
	if err != nil {
		t.Fatalf("authenticated session killed past the pre-auth deadline: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write on the spared session: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo on the spared session: %q %v", buf, err)
	}
}

// TestPreAuthMaxStreams caps the request streams an unauthenticated connection
// holds open; the stream past the cap is reset with H3_REQUEST_INCOMPLETE while
// the connection and the streams within the cap stay. Each stream writes its
// HEADERS frame type and a declared length but no body, so it parks exactly as
// a stalled auth would, each within the header cap.
func TestPreAuthMaxStreams(t *testing.T) {
	const cap = 3
	const total = 6
	addr := startPreAuthServer(t, nil, func(c *server.Config) { c.PreAuthMaxStreams = cap })
	_, conn, err := preAuthDial(t, addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")

	// 0x01 = HEADERS frame type, then a declared length; no payload follows,
	// so the stream parks in the server's read and counts against the cap.
	stall := []byte{0x01, 0x44, 0x00} // type=1, varint length 0x0400 (1024)
	reset := 0
	for i := 0; i < total; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		st, err := conn.OpenStreamSync(ctx)
		cancel()
		if err != nil {
			t.Fatalf("open stream %d: %v", i, err)
		}
		if _, err := st.Write(stall); err != nil {
			t.Fatalf("write stall %d: %v", i, err)
		}
		// Give the dispatcher a moment to peek this stream's frame type and
		// count it before the next opens, so the order is deterministic.
		time.Sleep(30 * time.Millisecond)
		_ = st.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
		if _, err := st.Read(make([]byte, 1)); err != nil {
			var se *quic.StreamError
			if errors.As(err, &se) {
				reset++
			} else if !isTimeout(err) {
				t.Fatalf("stream %d read: unexpected %v", i, err)
			}
		}
	}
	if reset != total-cap {
		t.Fatalf("reset %d pre-auth streams, want %d (cap %d of %d)", reset, total-cap, cap, total)
	}
	// The connection itself must still be up.
	if conn.Context().Err() != nil {
		t.Fatal("the connection was closed; the stream cap must reset only the excess stream")
	}
}

// countingPreAuthLimiter is a test server.PreAuthLimiter: a global cap with a
// live count and a refusal count. Its slots keep the closer the server hands
// them and count releases past the first, which the server must never make.
type countingPreAuthLimiter struct {
	mu            sync.Mutex
	cap           int
	live          int
	refused       int
	slots         []*countingPreAuthSlot
	extraReleases int
}

type countingPreAuthSlot struct {
	l         *countingPreAuthLimiter
	closeConn func()
	released  bool
}

func (l *countingPreAuthLimiter) Acquire(net.Addr) (server.PreAuthSlot, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.live >= l.cap {
		l.refused++
		return nil, false
	}
	l.live++
	s := &countingPreAuthSlot{l: l}
	l.slots = append(l.slots, s)
	return s, true
}

func (s *countingPreAuthSlot) SetCloser(closeConn func()) {
	s.l.mu.Lock()
	defer s.l.mu.Unlock()
	s.closeConn = closeConn
}

func (s *countingPreAuthSlot) Release() {
	s.l.mu.Lock()
	defer s.l.mu.Unlock()
	if s.released {
		s.l.extraReleases++
		return
	}
	s.released = true
	s.l.live--
}

func (l *countingPreAuthLimiter) liveN() int { l.mu.Lock(); defer l.mu.Unlock(); return l.live }
func (l *countingPreAuthLimiter) refusedN() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.refused
}

func (l *countingPreAuthLimiter) acquiredN() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.slots)
}

// closer is the closer the server handed slot i, nil before it did.
func (l *countingPreAuthLimiter) closer(i int) func() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if i >= len(l.slots) {
		return nil
	}
	return l.slots[i].closeConn
}

func (l *countingPreAuthLimiter) extraReleasesN() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.extraReleases
}

// TestPreAuthLimiterCapsConnections: once the cap is full of held
// unauthenticated connections, the next is refused (CONNECTION_REFUSED) before
// any state is kept for it.
func TestPreAuthLimiterCapsConnections(t *testing.T) {
	lim := &countingPreAuthLimiter{cap: 2}
	addr := startPreAuthServer(t, nil, func(c *server.Config) { c.PreAuthLimiter = lim })
	for i := 0; i < lim.cap; i++ {
		if _, _, err := preAuthDial(t, addr, time.Second); err != nil {
			t.Fatalf("connection %d within the cap was refused: %v", i, err)
		}
	}
	// Wait for both slots to be taken (Acquire runs on the first Initial).
	deadline := time.Now().Add(3 * time.Second)
	for lim.liveN() < lim.cap && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if _, _, err := preAuthDial(t, addr, time.Second); err == nil {
		t.Fatal("a connection past the pre-auth cap was admitted")
	}
	if lim.refusedN() == 0 {
		t.Fatal("the limiter recorded no refusal")
	}
}

// TestPreAuthLimiterReleasesOnAuth: a successful auth frees the slot at once, so
// far more authenticated sessions than the cap coexist from one source — what
// makes a per-source cap safe behind CGNAT/relay — and the connection's end
// does not release it a second time.
func TestPreAuthLimiterReleasesOnAuth(t *testing.T) {
	lim := &countingPreAuthLimiter{cap: 2}
	addr := startPreAuthServer(t, nil, func(c *server.Config) { c.PreAuthLimiter = lim })
	const n = 8 // >> cap
	var held []client.Client
	t.Cleanup(func() {
		for _, c := range held {
			_ = c.Close()
		}
	})
	for i := 0; i < n; i++ {
		c, _, err := client.NewClient(&client.Config{
			ServerAddr: addr,
			Auth:       "letmein",
			TLSConfig:  client.TLSConfig{InsecureSkipVerify: true, ServerName: "hs.b10d.test"},
			QUICConfig: client.QUICConfig{KeepAlivePeriod: 2 * time.Second, MaxIdleTimeout: 10 * time.Second},
		})
		if err != nil {
			t.Fatalf("authenticated client %d blocked by the pre-auth cap: %v", i, err)
		}
		held = append(held, c)
	}
	// Every authenticated session has released its slot, so the live count is
	// back at or near zero though n > cap sessions are held.
	deadline := time.Now().Add(3 * time.Second)
	for lim.liveN() > 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := lim.liveN(); got > 0 {
		t.Fatalf("pre-auth slots not released on auth: %d still held with %d sessions up", got, n)
	}
	for _, c := range held {
		_ = c.Close()
	}
	held = nil
	time.Sleep(200 * time.Millisecond) // the ends of the authenticated connections
	if got := lim.extraReleasesN(); got > 0 {
		t.Fatalf("%d slots released again at their connection's end after the auth released them", got)
	}
}

// TestPreAuthSlotCloser: once the handshake completed, a slot gets a way to end
// its connection, which is how a full limiter evicts a connection instead of
// refusing every newcomer. It closes an unauthenticated connection with
// H3_NO_ERROR, as an idle close, and leaves an authenticated one alone.
func TestPreAuthSlotCloser(t *testing.T) {
	lim := &countingPreAuthLimiter{cap: 8}
	addr := startPreAuthServer(t, nil, func(c *server.Config) { c.PreAuthLimiter = lim })

	cl, _, err := client.NewClient(&client.Config{
		ServerAddr: addr,
		Auth:       "letmein",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true, ServerName: "hs.b10d.test"},
		QUICConfig: client.QUICConfig{KeepAlivePeriod: 2 * time.Second, MaxIdleTimeout: 10 * time.Second},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer cl.Close()
	_, conn, err := preAuthDial(t, addr, time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.CloseWithError(0, "")
	deadline := time.Now().Add(3 * time.Second)
	for (lim.closer(0) == nil || lim.closer(1) == nil) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	authed, unauthed := lim.closer(0), lim.closer(1)
	if authed == nil || unauthed == nil {
		t.Fatal("a slot got no closer once its handshake completed")
	}

	start := time.Now()
	authed()
	unauthed()
	unauthed()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the closes took %v, want them to return at once", took)
	}
	preAuthClosedIdle(t, conn, 3*time.Second)

	tc, err := cl.TCP("echo:1")
	if err != nil {
		t.Fatalf("the slot's closer ended an authenticated session: %v", err)
	}
	defer tc.Close()
	if _, err := tc.Write([]byte("ping")); err != nil {
		t.Fatalf("write on the authenticated session: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo on the authenticated session: %q %v", buf, err)
	}
}

// TestPreAuthLimiterReleasesOnStalledHandshake is the pinned blocker: a
// connection whose handshake never completes must release its ConnContext slot
// by itself. quic-go calls ConnContext on the first Initial (before the
// handshake), then cancels the connection context when the handshake times out
// (Conn.run defers ctxCancel), which fires the release. Here a middlebox passes
// the client's first packet to the server and drops the rest, so the server
// creates the connection, keeps a slot, and never completes the handshake.
func TestPreAuthLimiterReleasesOnStalledHandshake(t *testing.T) {
	if testing.Short() {
		t.Skip("waits on the QUIC handshake-idle timeout")
	}
	real, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	stall := &oneInitialConn{PacketConn: real}
	lim := &countingPreAuthLimiter{cap: 4}
	addr := startPreAuthServer(t, stall, func(c *server.Config) { c.PreAuthLimiter = lim })

	// The client sends its Initial(s), the middlebox forwards only the first,
	// so the server makes the connection (takes a slot) and then stalls. Dial
	// in the background and watch the slot from the start: the server's own
	// handshake-idle timeout can fire before the client's Dial returns, so we
	// must observe the slot being taken before it is released.
	cpc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	ctr := &quic.Transport{Conn: cpc}
	t.Cleanup(func() { _ = ctr.Close(); _ = cpc.Close() })
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		_, _ = ctr.Dial(ctx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "hs.b10d.test"}, &quic.Config{MaxIdleTimeout: 30 * time.Second})
	}()
	deadline := time.Now().Add(4 * time.Second)
	for lim.liveN() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if lim.liveN() == 0 {
		t.Fatal("the server never took a pre-auth slot for the stalled handshake")
	}
	// The handshake-idle timeout (quic-go default 5s) must cancel the conn ctx
	// and release the slot with no help from us.
	deadline = time.Now().Add(15 * time.Second)
	for lim.liveN() > 0 && time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
	}
	if got := lim.liveN(); got > 0 {
		t.Fatalf("a stalled handshake's ConnContext slot was never released: %d still held", got)
	}
	if lim.closer(0) != nil {
		t.Fatal("a handshake that never completed was handed a closer")
	}
}

// oneInitialConn forwards the first datagram from each distinct client address
// to the server and drops the rest, stalling every handshake after its first
// packet. It is a middlebox in front of the real server socket.
type oneInitialConn struct {
	net.PacketConn
	mu   sync.Mutex
	seen map[string]int
}

func (c *oneInitialConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		n, addr, err := c.PacketConn.ReadFrom(p)
		if err != nil {
			return n, addr, err
		}
		c.mu.Lock()
		if c.seen == nil {
			c.seen = make(map[string]int)
		}
		c.seen[addr.String()]++
		first := c.seen[addr.String()] == 1
		c.mu.Unlock()
		if first {
			return n, addr, nil
		}
		// drop and read the next
	}
}

// TestVerifySourceAddress: when set, the callback is consulted on the Initial
// and a connection that asks for a Retry still completes the handshake (the
// Retry just costs a round-trip). Pins the field is wired to the transport.
func TestVerifySourceAddress(t *testing.T) {
	var mu sync.Mutex
	var seen []bool
	addr := startPreAuthServer(t, nil, func(c *server.Config) {
		c.VerifySourceAddress = func(net.Addr) bool {
			mu.Lock()
			defer mu.Unlock()
			first := len(seen) == 0
			seen = append(seen, true)
			return first // force a Retry on the first Initial only
		}
	})
	cl, _, err := client.NewClient(&client.Config{
		ServerAddr: addr,
		Auth:       "letmein",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true, ServerName: "hs.b10d.test"},
	})
	if err != nil {
		t.Fatalf("handshake with VerifySourceAddress set failed: %v", err)
	}
	defer cl.Close()
	mu.Lock()
	n := len(seen)
	mu.Unlock()
	if n == 0 {
		t.Fatal("VerifySourceAddress was never consulted")
	}
}

// deafConn is a client socket that hears nothing: every datagram to it is
// dropped, as a spoofed source never sees the answers sent to the address it
// forged.
type deafConn struct{ net.PacketConn }

func (c deafConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		if _, _, err := c.PacketConn.ReadFrom(p); err != nil {
			return 0, nil, err
		}
	}
}

// TestVerifySourceAddressBeforeConnContext pins quic-go's order: an Initial
// without a token goes to VerifySourceAddress before ConnContext, so a source
// answered with a Retry takes no PreAuthLimiter slot until it comes back with
// the token, and one that cannot (a spoofed one) takes none at all. A quic-go
// update that admits first would let a spoofed flood fill the limiter however
// eagerly the application asks for Retries.
func TestVerifySourceAddressBeforeConnContext(t *testing.T) {
	lim := &countingPreAuthLimiter{cap: 8}
	var asked atomic.Int32
	addr := startPreAuthServer(t, nil, func(c *server.Config) {
		c.PreAuthLimiter = lim
		c.VerifySourceAddress = func(net.Addr) bool { asked.Add(1); return true }
	})

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client listen: %v", err)
	}
	deaf := &quic.Transport{Conn: deafConn{pc}}
	t.Cleanup(func() { _ = deaf.Close(); _ = pc.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if _, err := deaf.Dial(ctx, addr, &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h3"}, ServerName: "hs.b10d.test"}, &quic.Config{}); err == nil {
		t.Fatal("a client that hears nothing completed a handshake")
	}
	if asked.Load() == 0 {
		t.Fatal("VerifySourceAddress was never consulted")
	}
	if got := lim.acquiredN(); got != 0 {
		t.Fatalf("a source that never answered the Retry took %d pre-auth slots", got)
	}

	cl, _, err := client.NewClient(&client.Config{
		ServerAddr: addr,
		Auth:       "letmein",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true, ServerName: "hs.b10d.test"},
	})
	if err != nil {
		t.Fatalf("a client that follows the Retry was refused: %v", err)
	}
	defer cl.Close()
	if got := lim.acquiredN(); got != 1 {
		t.Fatalf("a client that followed the Retry took %d pre-auth slots, want 1", got)
	}
}

var _ server.PreAuthLimiter = (*countingPreAuthLimiter)(nil)

// TestMaxIncomingUniStreams caps the client's unidirectional streams: with 3,
// the client opens three and the fourth OpenUniStreamSync blocks on the peer's
// limit; the default (0 -> quic-go's 100) admits the fourth.
func TestMaxIncomingUniStreams(t *testing.T) {
	open4 := func(t *testing.T, addr net.Addr) error {
		_, conn, err := preAuthDial(t, addr, time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer conn.CloseWithError(0, "")
		for i := 0; i < 3; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_, err := conn.OpenUniStreamSync(ctx)
			cancel()
			if err != nil {
				t.Fatalf("open uni stream %d: %v", i, err)
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = conn.OpenUniStreamSync(ctx)
		return err
	}
	t.Run("cap of 3 blocks the fourth", func(t *testing.T) {
		addr := startPreAuthServer(t, nil, func(c *server.Config) { c.QUICConfig.MaxIncomingUniStreams = 3 })
		if err := open4(t, addr); err == nil {
			t.Fatal("a fourth uni stream was admitted under a cap of 3")
		} else if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("fourth uni stream error = %v, want the peer limit to block it", err)
		}
	})
	t.Run("default admits the fourth", func(t *testing.T) {
		addr := startPreAuthServer(t, nil, nil)
		if err := open4(t, addr); err != nil {
			t.Fatalf("a fourth uni stream was blocked with no cap set: %v", err)
		}
	})
}
