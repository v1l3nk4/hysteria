package integration_tests

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/apernet/quic-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/apernet/hysteria/core/v2/client"
	coreErrs "github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/integration_tests/mocks"
	"github.com/apernet/hysteria/core/v2/server"
)

// trackerRecorder (b10d) is a ConnTracker that keeps what the server hands it.
type trackerRecorder struct {
	mu     sync.Mutex
	ids    []string
	closes []func()
}

func (r *trackerRecorder) TrackConn(id string, closeConn func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ids = append(r.ids, id)
	r.closes = append(r.closes, closeConn)
}

func (r *trackerRecorder) tracked() ([]string, []func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.ids...), append([]func(){}, r.closes...)
}

// trackedEchoOutbound answers every TCP request with an in-memory echo, and
// fails the test when a stream is dialled for a connection the tracker never
// got.
type trackedEchoOutbound struct {
	t       *testing.T
	tracker *trackerRecorder
}

func (o *trackedEchoOutbound) TCP(string) (net.Conn, error) {
	if ids, _ := o.tracker.tracked(); len(ids) == 0 {
		o.t.Error("a stream was dialled before TrackConn")
	}
	a, b := net.Pipe()
	go func() {
		_, _ = io.Copy(b, b)
		_ = b.Close()
	}()
	return a, nil
}

func (o *trackedEchoOutbound) UDP(string) (server.UDPConn, error) { return nil, errors.New("no udp") }
func (o *trackedEchoOutbound) CheckUDP(string) error              { return nil }

// TestServerConnTracker (b10d): the server hands ConnTracker one close per
// authenticated connection, with the id Authenticate returned, before the
// client gets its auth response; a failed auth is never tracked. The close
// returns at once and ends the connection, its open streams with it, with the
// code a TrafficLogger refusal sends (0x107); it may run again, also after the
// end, which is reported once, as any other.
func TestServerConnTracker(t *testing.T) {
	udpConn, udpAddr, err := serverConn()
	assert.NoError(t, err)
	tracker := &trackerRecorder{}
	auth := mocks.NewMockAuthenticator(t)
	auth.EXPECT().Authenticate(mock.Anything, "good", mock.Anything).Return(true, "conn-1")
	auth.EXPECT().Authenticate(mock.Anything, "bad", mock.Anything).Return(false, "")
	trafficLogger := mocks.NewMockTrafficLogger(t)
	trafficLogger.EXPECT().LogOnlineState("conn-1", true).Return().Once()
	offline := make(chan struct{})
	trafficLogger.EXPECT().LogOnlineState("conn-1", false).Run(func(string, bool) { close(offline) }).Return().Once()
	trafficLogger.EXPECT().LogTraffic("conn-1", mock.Anything, mock.Anything).Return(true).Maybe()
	trafficLogger.EXPECT().TraceStream(mock.Anything, mock.Anything).Return().Maybe()
	trafficLogger.EXPECT().UntraceStream(mock.Anything).Return().Maybe()
	s, err := server.NewServer(&server.Config{
		TLSConfig:     serverTLSConfig(),
		Conn:          udpConn,
		Outbound:      &trackedEchoOutbound{t: t, tracker: tracker},
		Authenticator: auth,
		TrafficLogger: trafficLogger,
		ConnTracker:   tracker,
		DisableUDP:    true,
	})
	assert.NoError(t, err)
	defer s.Close()
	go s.Serve()

	_, _, err = client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		Auth:       "bad",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.Error(t, err)
	if ids, _ := tracker.tracked(); len(ids) != 0 {
		t.Fatalf("a failed auth was tracked: %v", ids)
	}

	c, _, err := client.NewClient(&client.Config{
		ServerAddr: udpAddr,
		Auth:       "good",
		TLSConfig:  client.TLSConfig{InsecureSkipVerify: true},
	})
	assert.NoError(t, err)
	defer c.Close()
	ids, closes := tracker.tracked()
	if len(ids) != 1 || ids[0] != "conn-1" {
		t.Fatalf("tracked %v when the client got its auth response, want exactly [conn-1]", ids)
	}

	conn, err := c.TCP("echo:7")
	assert.NoError(t, err)
	_, err = conn.Write([]byte("ping"))
	assert.NoError(t, err)
	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	assert.NoError(t, err)
	assert.Equal(t, "ping", string(buf))

	start := time.Now()
	closes[0]()
	closes[0]()
	if took := time.Since(start); took > time.Second {
		t.Fatalf("the close took %v, want it to return at once", took)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(buf); err == nil {
		t.Fatal("the open stream survived the close")
	}
	select {
	case <-offline:
	case <-time.After(3 * time.Second):
		t.Fatal("the connection's end was not reported after its close")
	}
	_, err = c.TCP("echo:7")
	var closed coreErrs.ClosedError
	var appErr *quic.ApplicationError
	if !errors.As(err, &closed) || !errors.As(err, &appErr) || !appErr.Remote || appErr.ErrorCode != 0x107 {
		t.Fatalf("the client's next request got %v, want the server's close 0x107", err)
	}

	done := make(chan struct{})
	go func() {
		closes[0]()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a close after the connection ended blocked")
	}
	if ids, _ := tracker.tracked(); len(ids) != 1 {
		t.Fatalf("tracked %v after the close, want still one", ids)
	}
}
