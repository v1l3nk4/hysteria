package server

import (
	"bytes"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/apernet/quic-go"

	"github.com/apernet/hysteria/core/v2/internal/frag"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"
)

const (
	idleCleanupInterval = 1 * time.Second
	// maxSessionACLCache (b10d: 64, upstream 256) bounds the destinations a
	// session remembers a verdict for. Each key is a client-chosen string, so
	// the bound is what holds a session's cache to a few KiB.
	maxSessionACLCache = 64
)

// b10d: bounds on what a client can make the server hold before a session
// exists or between datagrams. A datagram outside them is dropped and the
// connection stays.
const (
	// maxRequestAddrLength is the longest "host:port" that can name anything:
	// a 254-byte DNS name (with its trailing dot) and ":65535". The protocol
	// allows 2048, which only ever serves to pin memory. handleTCPRequest
	// holds a stream's address to it too.
	maxRequestAddrLength = 254 + 6
	// maxFragCount bounds the fragments of one datagram, so what a session
	// holds for a datagram still in flight. Clients fragment to the QUIC
	// datagram size (about 1.2 KB): 16 cover about 18 KB, and sing-box's
	// 9000-byte TUN packets need 8.
	maxFragCount = 16
	// maxPendingSessions bounds, per connection, the sessions that exist only
	// because a datagram's first fragments arrived: no socket, no
	// EventLogger.New and no StreamLimiter.AllowUDP until the datagram is
	// whole, so nothing else counts them. Past it, a new session's fragment is
	// dropped; the client's next datagram on that session asks again.
	maxPendingSessions = 64
	// pendingSessionTimeout ends such a session once this long has passed
	// since its first fragment (the idle sweep): an honest datagram's
	// fragments arrive within a round trip of each other.
	pendingSessionTimeout = 5 * time.Second
)

// ErrRequestHookMore (b10d) lets a UDP RequestHook inspect a session's later
// datagrams without holding them back. Returned from RequestHook.UDP, the held
// packets are sent at once, and each later datagram is passed to the hook on its
// own as it goes out until the hook returns nil and done (stop inspecting) or
// another error (abort the session); ErrRequestHookMore again, or not done,
// asks for the next one.
var ErrRequestHookMore = errors.New("request hook: inspect more datagrams")

type udpIO interface {
	ReceiveMessage() (*protocol.UDPMessage, error)
	SendMessage([]byte, *protocol.UDPMessage) error
	Hook(packets [][]byte, reqAddr *string) (bool, error)
	UDP(reqAddr string) (UDPConn, error)
	CheckUDP(reqAddr string) error
}

type udpEventLogger interface {
	New(sessionID uint32, reqAddr string)
	Close(sessionID uint32, err error)
}

type udpSessionEntry struct {
	ID           uint32
	OverrideAddr string // Ignore the address in the UDP message, always use this if not empty
	OriginalAddr string // The original address in the UDP message
	D            *frag.Defragger
	Last         *utils.AtomicTime
	IO           udpIO

	DialFunc func(addr string) (UDPConn, error)
	ExitFunc func(err error)

	held     []*protocol.UDPMessage // Messages held back until the hook is done with them
	conn     UDPConn
	connLock sync.Mutex
	closed   bool

	// hookInspect (b10d): the RequestHook asked to inspect further datagrams of
	// this session (it returned ErrRequestHookMore on a prior datagram).
	hookInspect bool

	aclCache map[string]error

	// pending (b10d): the session has no socket because its first datagram is
	// still in fragments, since pendingSince (maxPendingSessions). Guarded by
	// the manager's mutex.
	pending      bool
	pendingSince time.Time
}

func newUDPSessionEntry(
	id uint32, io udpIO,
	dialFunc func(string) (UDPConn, error),
	exitFunc func(error),
) (e *udpSessionEntry) {
	e = &udpSessionEntry{
		ID:   id,
		D:    &frag.Defragger{},
		Last: utils.NewAtomicTime(time.Now()),
		IO:   io,

		DialFunc: dialFunc,
		ExitFunc: exitFunc,
	}

	return e
}

// CloseWithErr closes the session and calls ExitFunc with the given error.
// A nil error indicates the session is cleaned up due to timeout.
func (e *udpSessionEntry) CloseWithErr(err error) {
	// We need this lock to ensure not to create conn after session exit
	e.connLock.Lock()

	if e.closed {
		// Already closed
		e.connLock.Unlock()
		return
	}

	e.closed = true
	if e.conn != nil {
		_ = e.conn.Close()
	}
	e.connLock.Unlock()

	e.ExitFunc(err)
}

// Feed feeds a UDP message to the session.
// If the message itself is a complete message, or it completes a fragmented message,
// the message is written to the session's UDP connection, and the number of bytes
// written is returned. Otherwise, 0 and nil are returned.
// Until the connection is established, messages are held back instead, and are
// written together once the hook is done with them.
func (e *udpSessionEntry) Feed(msg *protocol.UDPMessage) (int, error) {
	e.Last.Set(time.Now())
	if msg.FragCount > 1 {
		// b10d: a fragment the defragger holds keeps a copy of its data, not
		// the whole QUIC datagram it arrived in.
		fragment := *msg
		fragment.Data = bytes.Clone(msg.Data)
		msg = &fragment
	}
	dfMsg := e.D.Feed(msg)
	if dfMsg == nil {
		// b10d: nor its address: a datagram takes the address of the fragment
		// that completes it. msg is the copy above.
		msg.Addr = ""
		return 0, nil
	}
	if e.conn != nil {
		if e.hookInspect {
			// b10d: the hook asked for more (ErrRequestHookMore). Each later
			// datagram is passed to it on its own as it goes out, with a
			// throwaway copy of the address: this inspection cannot rewrite
			// the target.
			hookAddr := dfMsg.Addr
			done, err := e.IO.Hook([][]byte{dfMsg.Data}, &hookAddr)
			switch {
			case errors.Is(err, ErrRequestHookMore), err == nil && !done:
				// Keep inspecting.
			case err == nil:
				e.hookInspect = false
			default:
				e.CloseWithErr(err)
				return 0, err
			}
		}
		return e.write(dfMsg)
	}

	e.held = append(e.held, dfMsg)
	packets := make([][]byte, len(e.held))
	for i, m := range e.held {
		packets[i] = m.Data
	}
	firstAddr := e.held[0].Addr
	addr := firstAddr
	done, err := e.IO.Hook(packets, &addr)
	if errors.Is(err, ErrRequestHookMore) {
		// b10d: send what is held and pass the hook every later datagram.
		e.hookInspect = true
		done, err = true, nil
	}
	if err != nil {
		e.CloseWithErr(err)
		return 0, err
	}
	if !done {
		return 0, nil
	}
	if err := e.initConn(firstAddr, addr); err != nil {
		return 0, err
	}
	if e.OverrideAddr == "" {
		e.aclCache = map[string]error{firstAddr: nil}
	}
	held := e.held
	e.held = nil
	total := 0
	for _, m := range held {
		n, err := e.write(m)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// write writes a message to the session's UDP connection.
func (e *udpSessionEntry) write(dfMsg *protocol.UDPMessage) (int, error) {
	addr := dfMsg.Addr
	if e.OverrideAddr != "" {
		addr = e.OverrideAddr
	} else if err := e.checkAddr(addr); err != nil {
		return 0, err
	}

	return e.conn.WriteTo(dfMsg.Data, addr)
}

// checkAddr checks outbound policy for the given address.
// The decision is cached in e.aclCache for future use.
func (e *udpSessionEntry) checkAddr(addr string) error {
	if decision, ok := e.aclCache[addr]; ok {
		return decision
	}
	decision := e.IO.CheckUDP(addr)
	if errors.Is(decision, errUDPDestLimited) {
		// b10d: refused for the peer's rate of new destinations, not for the
		// address: not remembered, so the next datagram there asks again.
		return decision
	}
	if len(e.aclCache) >= maxSessionACLCache {
		for k := range e.aclCache {
			delete(e.aclCache, k)
			break
		}
	}
	if e.aclCache == nil {
		e.aclCache = make(map[string]error, 4)
	}
	e.aclCache[addr] = decision
	return decision
}

// initConn initializes the UDP connection of the session to addr,
// which is what the hook turned the address of the first message into.
// If no error is returned, the e.conn is set to the new connection.
func (e *udpSessionEntry) initConn(firstAddr, addr string) error {
	// We need this lock to ensure not to create conn after session exit
	e.connLock.Lock()

	if e.closed {
		e.connLock.Unlock()
		return errors.New("session is closed")
	}

	conn, err := e.DialFunc(addr)
	if err != nil {
		// Fail fast if DialFunc failed
		// (usually indicates the connection has been rejected by the ACL)
		e.connLock.Unlock()
		// CloseWithErr acquires the connLock again
		e.CloseWithErr(err)
		return err
	}

	e.conn = conn

	if firstAddr != addr {
		// Hook changed the address, enable address override
		e.OverrideAddr = addr
		e.OriginalAddr = firstAddr
	}
	go e.receiveLoop()

	e.connLock.Unlock()
	return nil
}

// receiveLoop receives incoming UDP packets, packs them into UDP messages,
// and sends using the IO.
// Exit when either the underlying UDP connection returns error (e.g. closed),
// or the IO returns error when sending.
func (e *udpSessionEntry) receiveLoop() {
	udpBuf := make([]byte, protocol.MaxUDPSize)
	msgBuf := make([]byte, protocol.MaxUDPSize)
	for {
		udpN, rAddr, err := e.conn.ReadFrom(udpBuf)
		if err != nil {
			e.CloseWithErr(err)
			return
		}
		e.Last.Set(time.Now())

		if e.OriginalAddr != "" {
			// Use the original address in the opposite direction,
			// otherwise the QUIC clients or NAT on the client side
			// may not treat it as the same UDP session.
			rAddr = e.OriginalAddr
		}

		msg := &protocol.UDPMessage{
			SessionID: e.ID,
			PacketID:  0,
			FragID:    0,
			FragCount: 1,
			Addr:      rAddr,
			Data:      udpBuf[:udpN],
		}
		err = sendMessageAutoFrag(e.IO, msgBuf, msg)
		if err != nil {
			e.CloseWithErr(err)
			return
		}
	}
}

// sendMessageAutoFrag tries to send a UDP message as a whole first,
// but if it fails due to quic.ErrMessageTooLarge, it tries again by
// fragmenting the message.
func sendMessageAutoFrag(io udpIO, buf []byte, msg *protocol.UDPMessage) error {
	err := io.SendMessage(buf, msg)
	var errTooLarge *quic.DatagramTooLargeError
	if errors.As(err, &errTooLarge) {
		// Message too large, try fragmentation
		msg.PacketID = uint16(rand.Intn(0xFFFF)) + 1
		fMsgs := frag.FragUDPMessage(msg, int(errTooLarge.MaxDatagramPayloadSize))
		for _, fMsg := range fMsgs {
			err := io.SendMessage(buf, &fMsg)
			if err != nil {
				return err
			}
		}
		return nil
	} else {
		return err
	}
}

// udpSessionManager manages the lifecycle of UDP sessions.
// Each UDP session is identified by a SessionID, and corresponds to a UDP connection.
// A UDP session is created when a UDP message with a new SessionID is received.
// Similar to standard NAT, a UDP session is destroyed when no UDP message is received
// for a certain period of time (specified by idleTimeout).
type udpSessionManager struct {
	io          udpIO
	eventLogger udpEventLogger
	idleTimeout time.Duration

	mutex sync.RWMutex
	m     map[uint32]*udpSessionEntry
	// pending (b10d) counts the entries of m with pending set.
	pending int
}

func newUDPSessionManager(io udpIO, eventLogger udpEventLogger, idleTimeout time.Duration) *udpSessionManager {
	return &udpSessionManager{
		io:          io,
		eventLogger: eventLogger,
		idleTimeout: idleTimeout,
		m:           make(map[uint32]*udpSessionEntry),
	}
}

// Run runs the session manager main loop.
// Exit and returns error when the underlying io returns error (e.g. closed).
func (m *udpSessionManager) Run() error {
	stopCh := make(chan struct{})
	go m.idleCleanupLoop(stopCh)
	defer close(stopCh)
	defer m.cleanup(false)

	for {
		msg, err := m.io.ReceiveMessage()
		if err != nil {
			return err
		}
		m.feed(msg)
	}
}

func (m *udpSessionManager) idleCleanupLoop(stopCh <-chan struct{}) {
	ticker := time.NewTicker(idleCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.cleanup(true)
		case <-stopCh:
			return
		}
	}
}

func (m *udpSessionManager) cleanup(idleOnly bool) {
	// We use RLock here as we are only scanning the map, not deleting from it.
	m.mutex.RLock()
	timeoutEntry := make([]*udpSessionEntry, 0, len(m.m))
	now := time.Now()
	for _, entry := range m.m {
		if !idleOnly || now.Sub(entry.Last.Get()) > m.idleTimeout ||
			(entry.pending && now.Sub(entry.pendingSince) > pendingSessionTimeout) { // b10d
			timeoutEntry = append(timeoutEntry, entry)
		}
	}
	m.mutex.RUnlock()

	for _, entry := range timeoutEntry {
		// This eventually calls entry.ExitFunc,
		// where the m.mutex will be locked again to remove the entry from the map.
		entry.CloseWithErr(nil)
	}
}

func (m *udpSessionManager) feed(msg *protocol.UDPMessage) {
	// b10d: what no client sends is dropped before it can make a session or
	// hold a fragment: an address no name or literal can be, more fragments
	// than a datagram needs, a fragment beyond its own count.
	if len(msg.Addr) > maxRequestAddrLength || msg.FragCount > maxFragCount ||
		(msg.FragCount > 1 && msg.FragID >= msg.FragCount) {
		return
	}

	m.mutex.RLock()
	entry := m.m[msg.SessionID]
	m.mutex.RUnlock()

	// Create a new session if not exists
	if entry == nil {
		dialFunc := func(addr string) (UDPConn, error) {
			// Log the event
			m.eventLogger.New(msg.SessionID, addr)
			// Dial target
			return m.io.UDP(addr)
		}
		exitFunc := func(err error) {
			// Log the event
			m.eventLogger.Close(entry.ID, err)

			// Remove the session from the map
			m.mutex.Lock()
			delete(m.m, entry.ID)
			m.leavePendingLocked(entry)
			m.mutex.Unlock()
		}

		entry = newUDPSessionEntry(msg.SessionID, m.io, dialFunc, exitFunc)

		// Insert the session into the map
		m.mutex.Lock()
		if msg.FragCount > 1 {
			// b10d: its first datagram is not whole yet, so it gets no socket
			// and none of the caps behind New and AllowUDP see it.
			if m.pending >= maxPendingSessions {
				m.mutex.Unlock()
				return
			}
			entry.pending, entry.pendingSince = true, time.Now()
			m.pending++
		}
		m.m[msg.SessionID] = entry
		m.mutex.Unlock()
	}

	// Feed the message to the session
	// Feed (send) errors are ignored for now,
	// as some are temporary (e.g. invalid address)
	hadConn := entry.conn != nil // b10d: conn is set only by Feed, on this goroutine
	_, _ = entry.Feed(msg)
	if !hadConn && entry.conn != nil {
		m.mutex.Lock()
		m.leavePendingLocked(entry)
		m.mutex.Unlock()
	}
}

// leavePendingLocked (b10d) ends entry's pending state, if it has one: it got
// its socket, or it ended. m.mutex is held.
func (m *udpSessionManager) leavePendingLocked(entry *udpSessionEntry) {
	if entry.pending {
		entry.pending = false
		m.pending--
	}
}

func (m *udpSessionManager) Count() int {
	m.mutex.RLock()
	defer m.mutex.RUnlock()
	return len(m.m)
}
