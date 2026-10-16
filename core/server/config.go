package server

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/apernet/hysteria/core/v2/errors"
	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/hysteria/core/v2/internal/pmtud"
	"github.com/apernet/hysteria/core/v2/internal/utils"
	"github.com/apernet/quic-go"
)

const (
	defaultStreamReceiveWindow = 8388608                            // 8MB
	defaultConnReceiveWindow   = defaultStreamReceiveWindow * 5 / 2 // 20MB
	defaultMaxIdleTimeout      = 30 * time.Second
	defaultMaxIncomingStreams  = 1024
	defaultUDPIdleTimeout      = 60 * time.Second
)

type Config struct {
	TLSConfig             TLSConfig
	QUICConfig            QUICConfig
	Conn                  net.PacketConn
	StatelessResetKey     *quic.StatelessResetKey
	Cleanup               io.Closer
	RequestHook           RequestHook
	Outbound              Outbound
	CongestionConfig      CongestionConfig
	BandwidthConfig       BandwidthConfig
	IgnoreClientBandwidth bool
	DisableUDP            bool
	UDPIdleTimeout        time.Duration
	Authenticator         Authenticator
	EventLogger           EventLogger
	TrafficLogger         TrafficLogger
	MasqHandler           http.Handler
	// StreamLimiter (b10d) is consulted before the server opens a NEW
	// outbound proxy stream (TCP) or UDP session, and before a UDP session
	// sends to an address it has no verdict for. Returning false rejects
	// just that stream, session or datagram, leaving the rest of the
	// connection intact. Together they see every new outbound flow, so a
	// per-peer limiter is the analog of the agent's wg_ext nft `ct state
	// new` cap, which can't see hsd's locally-generated egress. nil disables
	// the check.
	StreamLimiter StreamLimiter
	// ConnTracker (b10d) is handed a way to close each connection the
	// Authenticator accepts, so the side that issued the id can end the
	// connection when it revokes the id. nil disables it.
	ConnTracker ConnTracker

	// b10d pre-auth limits: what a connection that has not authenticated may
	// hold. Each zero value keeps upstream's behaviour.
	//
	// MaxHeaderBytes caps a request's HEADERS frame (http3.Server's field of
	// the same name, also advertised as SETTINGS_MAX_FIELD_SECTION_SIZE).
	// http3 allocates the length the client declares before reading it, up
	// to the cap; a larger frame gets a 431. <=0 keeps http3's 1 MiB.
	MaxHeaderBytes int
	// PreAuthTimeout closes a connection that has not authenticated with
	// HTTP/3 NO_ERROR once it has been idle this long, as a keepalive timeout
	// would: it stands still while a request is in flight and runs again from
	// the end of the last one, and a successful auth cancels it. Not
	// http3.Server.IdleTimeout, which also ends authenticated connections
	// whose streams hysteria took over. 0 disables it.
	PreAuthTimeout time.Duration
	// PreAuthMaxAge closes a connection still unauthenticated this long after
	// its handshake, with HTTP/3 NO_ERROR, whatever its requests: they hold
	// off PreAuthTimeout, never this. A successful auth cancels it. 0 disables
	// it.
	PreAuthMaxAge time.Duration
	// PreAuthMaxStreams caps the request streams an unauthenticated connection
	// has open at once; a stream past it is reset (H3_REQUEST_INCOMPLETE) and
	// the connection stays. A stream counts once its first frame type arrived
	// and until it ends; streams opened after the auth never count. 0 disables
	// it.
	PreAuthMaxStreams int
	// PreAuthLimiter admits each new connection before its handshake and may
	// end it while it has not authenticated; until its slot is released its
	// connection receive window stays at InitialConnectionReceiveWindow. See
	// PreAuthLimiter. nil admits all.
	PreAuthLimiter PreAuthLimiter
	// VerifySourceAddress is quic.Transport's: true makes the server answer
	// that Initial with a Retry, so the client proves its address before the
	// server keeps any state for it. nil never asks.
	VerifySourceAddress func(net.Addr) bool
}

// fill fills the fields that are not set by the user with default values when possible,
// and returns an error if the user has not set a required field, or if a field is invalid.
func (c *Config) fill() error {
	if len(c.TLSConfig.Certificates) == 0 && c.TLSConfig.GetCertificate == nil {
		return errors.ConfigError{Field: "TLSConfig", Reason: "must set at least one of Certificates or GetCertificate"}
	}
	if c.QUICConfig.InitialStreamReceiveWindow == 0 {
		c.QUICConfig.InitialStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.InitialStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxStreamReceiveWindow == 0 {
		c.QUICConfig.MaxStreamReceiveWindow = defaultStreamReceiveWindow
	} else if c.QUICConfig.MaxStreamReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxStreamReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.InitialConnectionReceiveWindow == 0 {
		c.QUICConfig.InitialConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.InitialConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.InitialConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxConnectionReceiveWindow == 0 {
		c.QUICConfig.MaxConnectionReceiveWindow = defaultConnReceiveWindow
	} else if c.QUICConfig.MaxConnectionReceiveWindow < 16384 {
		return errors.ConfigError{Field: "QUICConfig.MaxConnectionReceiveWindow", Reason: "must be at least 16384"}
	}
	if c.QUICConfig.MaxIdleTimeout == 0 {
		c.QUICConfig.MaxIdleTimeout = defaultMaxIdleTimeout
	} else if c.QUICConfig.MaxIdleTimeout < 4*time.Second || c.QUICConfig.MaxIdleTimeout > 120*time.Second {
		return errors.ConfigError{Field: "QUICConfig.MaxIdleTimeout", Reason: "must be between 4s and 120s"}
	}
	if c.QUICConfig.MaxIncomingStreams == 0 {
		c.QUICConfig.MaxIncomingStreams = defaultMaxIncomingStreams
	} else if c.QUICConfig.MaxIncomingStreams < 8 {
		return errors.ConfigError{Field: "QUICConfig.MaxIncomingStreams", Reason: "must be at least 8"}
	}
	if c.QUICConfig.MaxIncomingUniStreams != 0 && c.QUICConfig.MaxIncomingUniStreams < 3 {
		return errors.ConfigError{Field: "QUICConfig.MaxIncomingUniStreams", Reason: "must be at least 3"}
	}
	if c.PreAuthTimeout < 0 {
		return errors.ConfigError{Field: "PreAuthTimeout", Reason: "must not be negative"}
	}
	if c.PreAuthMaxAge < 0 {
		return errors.ConfigError{Field: "PreAuthMaxAge", Reason: "must not be negative"}
	}
	if c.PreAuthMaxStreams < 0 {
		return errors.ConfigError{Field: "PreAuthMaxStreams", Reason: "must not be negative"}
	}
	c.QUICConfig.DisablePathMTUDiscovery = c.QUICConfig.DisablePathMTUDiscovery || pmtud.DisablePathMTUDiscovery
	var err error
	c.CongestionConfig.Type, err = congestion.NormalizeType(c.CongestionConfig.Type)
	if err != nil {
		return errors.ConfigError{Field: "CongestionConfig.Type", Reason: err.Error()}
	}
	if c.CongestionConfig.Type == congestion.TypeBBR {
		c.CongestionConfig.BBRProfile, err = congestion.NormalizeBBRProfile(c.CongestionConfig.BBRProfile)
		if err != nil {
			return errors.ConfigError{Field: "CongestionConfig.BBRProfile", Reason: err.Error()}
		}
	}
	if c.Conn == nil {
		return errors.ConfigError{Field: "Conn", Reason: "must be set"}
	}
	if c.Outbound == nil {
		c.Outbound = &defaultOutbound{}
	}
	if c.BandwidthConfig.MaxTx != 0 && c.BandwidthConfig.MaxTx < 65536 {
		return errors.ConfigError{Field: "BandwidthConfig.MaxTx", Reason: "must be at least 65536"}
	}
	if c.BandwidthConfig.MaxRx != 0 && c.BandwidthConfig.MaxRx < 65536 {
		return errors.ConfigError{Field: "BandwidthConfig.MaxRx", Reason: "must be at least 65536"}
	}
	if c.UDPIdleTimeout == 0 {
		c.UDPIdleTimeout = defaultUDPIdleTimeout
	} else if c.UDPIdleTimeout < 2*time.Second || c.UDPIdleTimeout > 600*time.Second {
		return errors.ConfigError{Field: "UDPIdleTimeout", Reason: "must be between 2s and 600s"}
	}
	if c.Authenticator == nil {
		return errors.ConfigError{Field: "Authenticator", Reason: "must be set"}
	}
	return nil
}

// TLSConfig contains the TLS configuration fields that we want to expose to the user.
type TLSConfig struct {
	Certificates   []tls.Certificate
	GetCertificate func(info *tls.ClientHelloInfo) (*tls.Certificate, error)
	ClientCAs      *x509.CertPool
	ECHKeys        []tls.EncryptedClientHelloKey
	GetECHKeys     func(info *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error)
}

// QUICConfig contains the QUIC configuration fields that we want to expose to the user.
type QUICConfig struct {
	InitialStreamReceiveWindow     uint64
	MaxStreamReceiveWindow         uint64
	InitialConnectionReceiveWindow uint64
	MaxConnectionReceiveWindow     uint64
	MaxIdleTimeout                 time.Duration
	MaxIncomingStreams             int64
	DisablePathMTUDiscovery        bool // The server may still override this to true on unsupported platforms.
	DisableGSO                     bool
	DisableStatelessReset          bool
	// MaxIncomingUniStreams (b10d) caps the client's unidirectional streams
	// open at once. HTTP/3 uses three (control, QPACK encoder and decoder);
	// 0 keeps quic-go's 100, anything else must be at least 3.
	MaxIncomingUniStreams int64
	// DisableVersionNegotiation (b10d) stops the server from answering a long
	// header of a version it does not speak with a Version Negotiation
	// packet (quic.Transport.DisableVersionNegotiationPackets).
	// DisableStatelessReset alone leaves that answer: behind an obfuscator
	// with no MAC (Salamander) a random datagram decodes to such a header now
	// and then, so a listener that must stay silent to blind probes sets
	// both. Hysteria clients speak QUIC v1 only and never need VN.
	DisableVersionNegotiation bool
}

type CongestionConfig struct {
	Type       string
	BBRProfile string
}

// RequestHook allows filtering and modifying requests before the server connects to the remote.
// A request will only be hooked if Check returns true.
// The returned byte slice, if not empty, will be sent to the remote before proxying - this is
// mainly for "putting back" the content read from the client for sniffing, etc.
// Return a non-nil error to abort the connection.
// For UDP, the first packets of a session are held back until the hook is done with them:
// UDP is called with all the packets held so far each time a new one arrives, and returns
// false to wait for the next one. The hook must give up eventually, as held packets are only
// sent (as-is, to the possibly modified reqAddr) once it returns true.
//
// b10d: TCP and UDP also receive the authenticated id (authID), so a hook can
// attribute a verdict to the peer (the P2P penalty ladder in hsd). UDP may also
// return ErrRequestHookMore to see the session's later datagrams without holding
// them back.
type RequestHook interface {
	Check(isUDP bool, reqAddr string) bool
	TCP(authID string, stream HyStream, reqAddr *string) ([]byte, error)
	UDP(authID string, packets [][]byte, reqAddr *string) (done bool, err error)
}

// Outbound provides the implementation of how the server should connect to remote servers.
// Although UDP includes a reqAddr, the implementation does not necessarily have to use it
// to make a "connected" UDP connection that does not accept packets from other addresses.
// In fact, the default implementation simply uses net.ListenUDP for a "full-cone" behavior.
// CheckUDP is used to check if a UDP packet to reqAddr is permitted (useful for e.g. ACL).
type Outbound interface {
	TCP(reqAddr string) (net.Conn, error)
	UDP(reqAddr string) (UDPConn, error)
	CheckUDP(reqAddr string) error
}

// UDPConn is like net.PacketConn, but uses string for addresses.
type UDPConn interface {
	ReadFrom(b []byte) (int, string, error)
	WriteTo(b []byte, addr string) (int, error)
	Close() error
}

type defaultOutbound struct{}

var defaultOutboundDialer = net.Dialer{
	Timeout: 10 * time.Second,
}

func (o *defaultOutbound) TCP(reqAddr string) (net.Conn, error) {
	return defaultOutboundDialer.Dial("tcp", reqAddr)
}

func (o *defaultOutbound) UDP(reqAddr string) (UDPConn, error) {
	conn, err := net.ListenUDP("udp", nil)
	if err != nil {
		return nil, err
	}
	return &defaultUDPConn{conn}, nil
}

func (o *defaultOutbound) CheckUDP(reqAddr string) error {
	return nil
}

type defaultUDPConn struct {
	*net.UDPConn
}

func (c *defaultUDPConn) ReadFrom(b []byte) (int, string, error) {
	n, addr, err := c.UDPConn.ReadFrom(b)
	if addr != nil {
		return n, addr.String(), err
	} else {
		return n, "", err
	}
}

func (c *defaultUDPConn) WriteTo(b []byte, addr string) (int, error) {
	uAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return 0, err
	}
	return c.UDPConn.WriteTo(b, uAddr)
}

// BandwidthConfig describes the maximum bandwidth that the server can use, in bytes per second.
type BandwidthConfig struct {
	MaxTx                   uint64
	MaxRx                   uint64
	DisableLossCompensation bool
}

// Authenticator is an interface that provides authentication logic.
type Authenticator interface {
	Authenticate(addr net.Addr, auth string, tx uint64) (ok bool, id string)
}

// EventLogger is an interface that provides logging logic.
type EventLogger interface {
	Connect(addr net.Addr, id string, tx uint64)
	Disconnect(addr net.Addr, id string, err error)
	TCPRequest(addr net.Addr, id, reqAddr string)
	TCPError(addr net.Addr, id, reqAddr string, err error)
	UDPRequest(addr net.Addr, id string, sessionID uint32, reqAddr string)
	UDPError(addr net.Addr, id string, sessionID uint32, err error)
}

type HyStream interface {
	StreamID() quic.StreamID
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetDeadline(t time.Time) error
}

// TrafficLogger is an interface that provides traffic logging logic.
// Tx/Rx in this context refers to the server-remote (proxy target) perspective.
// Tx is the bytes sent from the server to the remote.
// Rx is the bytes received by the server from the remote.
// Apart from logging, the Log function can also return false to signal
// that the client should be disconnected. This can be used to implement
// bandwidth limits or post-connection authentication, for example.
// The implementation of this interface must be thread-safe.
type TrafficLogger interface {
	LogTraffic(id string, tx, rx uint64) (ok bool)
	LogOnlineState(id string, online bool)
	TraceStream(stream HyStream, stats *StreamStats)
	UntraceStream(stream HyStream)
}

// StreamLimiter (b10d) gates the creation of new proxy streams / UDP
// sessions per authenticated peer. AllowTCP/AllowUDP receive the
// authenticated peer id and the requested target address and return
// false to reject just that one stream/session (the connection stays
// up). The implementation must be thread-safe.
type StreamLimiter interface {
	AllowTCP(id, reqAddr string) bool
	AllowUDP(id, reqAddr string) bool
	// AllowUDPDest is asked before a UDP session sends to an address it has
	// no verdict for: one of its new destinations (its first address
	// excepted, which AllowUDP covered). false drops that datagram and is
	// not remembered, so the session's next datagram there asks again.
	AllowUDPDest(id, reqAddr string) bool
}

// ConnTracker (b10d) lets the application end at once a connection whose id
// it revokes: a TrafficLogger returning false ends a connection only at its
// next byte, which an idle stream or UDP session never moves. TrackConn is
// called once per connection whose auth succeeded, with the id Authenticate
// returned, before the connection counts as authenticated and before the auth
// response is written, so nothing of the connection is served before it
// returns. It must not block.
//
// closeConn closes the whole connection, every stream and UDP session of it,
// with the code a TrafficLogger refusal sends. It returns at once and may be
// called from any goroutine, more than once, and after the connection ended.
// The end is reported as any other: TrafficLogger.LogOnlineState(id, false)
// and EventLogger.Disconnect.
type ConnTracker interface {
	TrackConn(id string, closeConn func())
}

// PreAuthLimiter (b10d) bounds the connections that have not authenticated.
// Acquire is called once per new connection, with the source address of its
// first Initial, before the server keeps any state for it: ok=false refuses
// the connection (CONNECTION_REFUSED). quic-go asks VerifySourceAddress about
// an Initial without a token first, so a source it answers with a Retry
// reaches Acquire only once it proved its address; any other is unproven.
// Must be safe for concurrent use and must not block: quic-go calls it on the
// goroutine that reads every packet.
//
// While a connection holds an unreleased slot, the server never grows its
// connection receive window past QUICConfig.InitialConnectionReceiveWindow,
// so whatever it leaves unread (request bodies, the QPACK streams) stays
// within that window however much it sends that the server reads; from the
// release on, the window grows as quic-go tunes it.
type PreAuthLimiter interface {
	Acquire(remote net.Addr) (slot PreAuthSlot, ok bool)
}

// PreAuthSlot (b10d) is one admitted connection's place in a PreAuthLimiter.
// The server calls Release exactly once: at the connection's successful auth,
// or when it ends unauthenticated, a handshake that never completes included.
// Once the handshake completed, before any request of the connection is
// served, it calls SetCloser, at most once, with a way to end the connection:
// closeConn closes it with HTTP/3 NO_ERROR, as an idle close would, unless it
// authenticated by then. closeConn returns at once and may be called from any
// goroutine, more than once, and after the connection ended. A connection
// whose handshake never completes gets no SetCloser, and one that ends as it
// completes may get it after Release. Neither method may block.
type PreAuthSlot interface {
	SetCloser(closeConn func())
	Release()
}

type StreamState int

const (
	// StreamStateInitial indicates the initial state of a stream.
	// Client has opened the stream, but we have not received the proxy request yet.
	StreamStateInitial StreamState = iota

	// StreamStateHooking indicates that the hook (usually sniff) is processing.
	// Client has sent the proxy request, but sniff requires more data to complete.
	StreamStateHooking

	// StreamStateConnecting indicates that we are connecting to the proxy target.
	StreamStateConnecting

	// StreamStateEstablished indicates the proxy is established.
	StreamStateEstablished

	// StreamStateClosed indicates the stream is closed.
	StreamStateClosed
)

func (s StreamState) String() string {
	switch s {
	case StreamStateInitial:
		return "init"
	case StreamStateHooking:
		return "hook"
	case StreamStateConnecting:
		return "connect"
	case StreamStateEstablished:
		return "estab"
	case StreamStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

type StreamStats struct {
	State utils.Atomic[StreamState]

	AuthID      string
	ConnID      uint32
	InitialTime time.Time

	ReqAddr       utils.Atomic[string]
	HookedReqAddr utils.Atomic[string]

	Tx atomic.Uint64
	Rx atomic.Uint64

	LastActiveTime utils.Atomic[time.Time]
}

func (s *StreamStats) setHookedReqAddr(addr string) {
	if addr != s.ReqAddr.Load() {
		s.HookedReqAddr.Store(addr)
	}
}
