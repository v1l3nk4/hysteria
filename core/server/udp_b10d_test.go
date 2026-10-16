package server

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/apernet/hysteria/core/v2/internal/protocol"
)

// b10d: the bounds feed and checkAddr put on what a client can make the server
// hold (udp.go). A fake udpIO stands in for the connection; feed is called
// directly, on the test goroutine, as Run would.

type boundsIO struct {
	mu       sync.Mutex
	dials    []string
	checks   []string
	checkErr func(addr string) error
	writes   []string
	data     []string
}

func (f *boundsIO) ReceiveMessage() (*protocol.UDPMessage, error)  { select {} }
func (f *boundsIO) SendMessage([]byte, *protocol.UDPMessage) error { return nil }
func (f *boundsIO) Hook([][]byte, *string) (bool, error)           { return true, nil }

func (f *boundsIO) UDP(addr string) (UDPConn, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dials = append(f.dials, addr)
	return &boundsConn{io: f, closed: make(chan struct{})}, nil
}

func (f *boundsIO) CheckUDP(addr string) error {
	f.mu.Lock()
	f.checks = append(f.checks, addr)
	check := f.checkErr
	f.mu.Unlock()
	if check != nil {
		return check(addr)
	}
	return nil
}

func (f *boundsIO) counts() (dials, checks, writes int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.dials), len(f.checks), len(f.writes)
}

type boundsConn struct {
	io     *boundsIO
	once   sync.Once
	closed chan struct{}
}

func (c *boundsConn) ReadFrom([]byte) (int, string, error) {
	<-c.closed
	return 0, "", errors.New("closed")
}

func (c *boundsConn) WriteTo(b []byte, addr string) (int, error) {
	c.io.mu.Lock()
	c.io.writes = append(c.io.writes, addr)
	c.io.data = append(c.io.data, string(b))
	c.io.mu.Unlock()
	return len(b), nil
}

func (c *boundsConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

type boundsEvents struct {
	mu          sync.Mutex
	news, ended int
}

func (e *boundsEvents) New(uint32, string) {
	e.mu.Lock()
	e.news++
	e.mu.Unlock()
}

func (e *boundsEvents) Close(uint32, error) {
	e.mu.Lock()
	e.ended++
	e.mu.Unlock()
}

func (e *boundsEvents) counts() (news, ended int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.news, e.ended
}

func newBoundsManager(t *testing.T) (*udpSessionManager, *boundsIO, *boundsEvents) {
	t.Helper()
	io, ev := &boundsIO{}, &boundsEvents{}
	m := newUDPSessionManager(io, ev, time.Minute)
	t.Cleanup(func() { m.cleanup(false) })
	return m, io, ev
}

func fragment(sid uint32, pkt uint16, id, count uint8, addr, data string) *protocol.UDPMessage {
	return &protocol.UDPMessage{SessionID: sid, PacketID: pkt, FragID: id, FragCount: count, Addr: addr, Data: []byte(data)}
}

func (m *udpSessionManager) entries() (all, pending int) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.m), m.pending
}

func (m *udpSessionManager) entry(sid uint32) *udpSessionEntry {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return m.m[sid]
}

// TestUDPFeedDropsWhatNoClientSends: an address longer than any host:port, a
// datagram in more than maxFragCount fragments and a fragment beyond its count
// make no session and hold nothing; the longest real address and the most
// fragments a datagram may come in still work.
func TestUDPFeedDropsWhatNoClientSends(t *testing.T) {
	m, io, ev := newBoundsManager(t)
	longest := strings.Repeat("a", maxRequestAddrLength-6) + ":65535"
	m.feed(fragment(1, 0, 0, 1, longest+"0", "x"))
	m.feed(fragment(2, 1, 0, maxFragCount+1, "192.0.2.1:9", "x"))
	m.feed(fragment(3, 1, 2, 2, "192.0.2.1:9", "x"))
	if news, _ := ev.counts(); news != 0 {
		t.Fatalf("New %d after datagrams no client sends, want none", news)
	}
	if all, _ := m.entries(); all != 0 {
		t.Fatalf("entries %d after datagrams no client sends, want none", all)
	}
	m.feed(fragment(4, 0, 0, 1, longest, "x"))
	m.feed(fragment(5, 1, 0, maxFragCount, "192.0.2.1:9", "x"))
	if dials, _, _ := io.counts(); dials != 1 {
		t.Fatalf("dials %d, want 1: the longest address must still open a session", dials)
	}
	if all, pending := m.entries(); all != 2 || pending != 1 {
		t.Fatalf("entries %d (pending %d), want 2 (1): a datagram in %d fragments must wait for its rest", all, pending, maxFragCount)
	}
}

// TestUDPPendingSessionsBounded: first fragments of new sessions make at most
// maxPendingSessions entries, none announced; a completed datagram turns its
// entry into a session and frees its place, and so does an entry that ends.
func TestUDPPendingSessionsBounded(t *testing.T) {
	m, io, ev := newBoundsManager(t)
	for sid := uint32(1); sid <= 1000; sid++ {
		m.feed(fragment(sid, 7, 0, 2, "192.0.2.1:9", "a"))
	}
	if all, pending := m.entries(); all != maxPendingSessions || pending != maxPendingSessions {
		t.Fatalf("after 1000 first fragments: entries %d, pending %d; want %d", all, pending, maxPendingSessions)
	}
	if dials, _, _ := io.counts(); dials != 0 {
		t.Fatalf("dials %d for incomplete datagrams", dials)
	}
	if news, _ := ev.counts(); news != 0 {
		t.Fatalf("New %d for incomplete datagrams", news)
	}
	m.feed(fragment(1, 7, 1, 2, "192.0.2.1:9", "b")) // completes session 1
	if dials, _, writes := io.counts(); dials != 1 || writes != 1 {
		t.Fatalf("completed datagram: dials %d writes %d, want 1 and 1", dials, writes)
	}
	if all, pending := m.entries(); all != maxPendingSessions || pending != maxPendingSessions-1 {
		t.Fatalf("after completing one: entries %d, pending %d", all, pending)
	}
	m.feed(fragment(2000, 7, 0, 2, "192.0.2.1:9", "a"))
	if _, pending := m.entries(); pending != maxPendingSessions {
		t.Fatalf("a freed place was not taken: pending %d", pending)
	}
	m.feed(fragment(3000, 7, 0, 2, "192.0.2.1:9", "a"))
	if all, _ := m.entries(); all != maxPendingSessions+1 {
		t.Fatalf("entries %d past the cap, want %d", all, maxPendingSessions+1)
	}
	m.cleanup(false)
	if all, pending := m.entries(); all != 0 || pending != 0 {
		t.Fatalf("after cleanup: entries %d, pending %d", all, pending)
	}
	// A whole datagram of a new session never waits on the cap.
	for sid := uint32(1); sid <= maxPendingSessions; sid++ {
		m.feed(fragment(10000+sid, 7, 0, 2, "192.0.2.1:9", "a"))
	}
	m.feed(fragment(20000, 0, 0, 1, "192.0.2.1:9", "whole"))
	if dials, _, _ := io.counts(); dials != 2 {
		t.Fatalf("a whole datagram was held back by the pending cap: dials %d", dials)
	}
}

// TestUDPPendingSessionsTimeOut: the idle sweep ends a session still waiting
// for the rest of its first datagram once pendingSessionTimeout has passed
// since its first fragment, which frees its place, long before the idle
// timeout; a session that got its socket is left to the idle timeout.
func TestUDPPendingSessionsTimeOut(t *testing.T) {
	m, io, ev := newBoundsManager(t)
	for sid := uint32(1); sid <= 3; sid++ {
		m.feed(fragment(sid, 7, 0, 2, "192.0.2.1:9", "a"))
	}
	m.feed(fragment(3, 7, 1, 2, "192.0.2.1:9", "b")) // session 3 gets its socket
	backdate := func(sid uint32) {
		e := m.entry(sid)
		m.mutex.Lock()
		e.pendingSince = e.pendingSince.Add(-pendingSessionTimeout - time.Second)
		m.mutex.Unlock()
	}
	backdate(1)
	backdate(3)
	m.cleanup(true)
	if m.entry(1) != nil {
		t.Fatal("a session waiting for its first datagram outlived pendingSessionTimeout")
	}
	if m.entry(2) == nil || m.entry(3) == nil {
		t.Fatal("the sweep ended a session that is young, or no longer pending")
	}
	if all, pending := m.entries(); all != 2 || pending != 1 {
		t.Fatalf("entries %d, pending %d after the sweep; want 2 and 1", all, pending)
	}
	if _, ended := ev.counts(); ended != 1 {
		t.Fatalf("Close reported %d times, want once for the swept session", ended)
	}
	if dials, _, _ := io.counts(); dials != 1 {
		t.Fatalf("dials %d, want only session 3's", dials)
	}
}

// TestUDPHeldFragmentKeepsOnlyItsData: a fragment waiting for the rest of its
// datagram holds a copy of its own bytes, not the received QUIC datagram they
// sit in, and no address: the datagram goes to the address of the fragment
// that completes it.
func TestUDPHeldFragmentKeepsOnlyItsData(t *testing.T) {
	m, io, _ := newBoundsManager(t)
	received := []byte("header|first-")
	first := &protocol.UDPMessage{SessionID: 1, PacketID: 9, FragID: 0, FragCount: 2, Addr: "192.0.2.1:9", Data: received[len("header|"):]}
	m.feed(first)
	held := reflect.ValueOf(m.entry(1).D).Elem().FieldByName("frags").Index(0).Elem()
	if addr := held.FieldByName("Addr").String(); addr != "" {
		t.Fatalf("a held fragment keeps the address %q", addr)
	}
	if held.FieldByName("Data").Pointer() == reflect.ValueOf(first.Data).Pointer() {
		t.Fatal("a held fragment's data still points into the received datagram")
	}
	copy(received, "XXXXXXXXXXXXX") // the received datagram's buffer goes on to other use
	m.feed(fragment(1, 9, 1, 2, "192.0.2.1:9", "second"))
	io.mu.Lock()
	defer io.mu.Unlock()
	if len(io.dials) != 1 || io.dials[0] != "192.0.2.1:9" || len(io.data) != 1 || io.data[0] != "first-second" {
		t.Fatalf("dials %q, written %q; want one session to 192.0.2.1:9 sent first-second", io.dials, io.data)
	}
}

// TestUDPDestLimitedIsNotCached: a destination the limiter refuses is dropped
// and asked about again on the next datagram; the session lives on and other
// destinations are unaffected.
func TestUDPDestLimitedIsNotCached(t *testing.T) {
	m, io, _ := newBoundsManager(t)
	refuse := true
	io.checkErr = func(addr string) error {
		if addr == "192.0.2.2:9" && refuse {
			return errUDPDestLimited
		}
		return nil
	}
	m.feed(fragment(1, 0, 0, 1, "192.0.2.1:9", "first")) // the session's first address: no check
	m.feed(fragment(1, 0, 0, 1, "192.0.2.2:9", "refused"))
	m.feed(fragment(1, 0, 0, 1, "192.0.2.3:9", "other"))
	if _, checks, writes := io.counts(); checks != 2 || writes != 2 {
		t.Fatalf("checks %d writes %d, want 2 and 2 (first and other written)", checks, writes)
	}
	refuse = false
	m.feed(fragment(1, 0, 0, 1, "192.0.2.2:9", "again"))
	m.feed(fragment(1, 0, 0, 1, "192.0.2.2:9", "cached"))
	if _, checks, writes := io.counts(); checks != 3 || writes != 4 {
		t.Fatalf("checks %d writes %d, want 3 and 4: the refusal must not be cached, the pass must", checks, writes)
	}
}

// TestUDPACLCacheBounded: a session sending to ever-new addresses keeps at most
// 64 verdicts (upstream keeps 256), each keyed by a client-chosen string.
func TestUDPACLCacheBounded(t *testing.T) {
	m, _, _ := newBoundsManager(t)
	m.feed(fragment(1, 0, 0, 1, "192.0.2.1:9", "first"))
	for i := 0; i < 1000; i++ {
		m.feed(fragment(1, 0, 0, 1, fmt.Sprintf("name-%d.example:%d", i, 1+i%65535), "x"))
	}
	if n := len(m.entry(1).aclCache); n > 64 {
		t.Fatalf("aclCache holds %d, want at most 64", n)
	}
}
