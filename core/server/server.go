package server

import (
	"context"
	crand "crypto/rand"
	"crypto/tls"
	"errors"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/apernet/quic-go/quicvarint"

	"github.com/apernet/hysteria/core/v2/internal/congestion"
	"github.com/apernet/hysteria/core/v2/internal/protocol"
	"github.com/apernet/hysteria/core/v2/internal/utils"
)

const (
	closeErrCodeOK                  = 0x100 // HTTP3 ErrCodeNoError
	closeErrCodeTrafficLimitReached = 0x107 // HTTP3 ErrCodeExcessiveLoad
)

// errUDPSessionLimited (b10d) is returned by udpIOImpl.UDP when the
// StreamLimiter rejects a NEW UDP session; the dialFunc surfaces it so
// the session is never created and the datagram is dropped, without
// tearing down the connection.
var errUDPSessionLimited = errors.New("udp session rate limited")

// errUDPDestLimited (b10d) is what udpIOImpl.CheckUDP answers when the
// StreamLimiter refuses a session's new destination: checkAddr does not cache
// it, and the datagram is dropped without ending the session.
var errUDPDestLimited = errors.New("udp destination rate limited")

// MaxBlockedUDPSenders (b10d) is how many of a connection's UDP sessions may be
// sending a datagram to the client at once. A session's reader waits in
// SendMessage while the connection's DATAGRAM queue is full (32 frames in
// quic-go) or the TrafficLogger holds it to a rate, and a waiting reader leaves
// its socket unread: the kernel fills it to its receive buffer, charged to this
// process, and a client that stops acknowledging keeps it full for as long as
// it likes. Past this many, a session's datagram is dropped instead and its
// reader goes back to draining its socket, so at most this many socket buffers
// of a connection fill, however many sessions it has. A light flow (a DNS
// answer) still gets a slot beside dozens of bulk sessions waiting on a capped
// peer's rate.
const MaxBlockedUDPSenders = 64

// errPreAuthRefused (b10d) is what preAuthConnContext returns for a connection
// the PreAuthLimiter refuses: quic-go answers it CONNECTION_REFUSED, what any
// QUIC server at its connection limit sends.
var errPreAuthRefused = errors.New("pre-auth connection limit reached")

// errTooManyPreAuthStreams (b10d) refuses a request stream past
// PreAuthMaxStreams: http3 resets it (H3_REQUEST_INCOMPLETE), the connection
// stays.
var errTooManyPreAuthStreams = errors.New("too many pre-auth streams")

// preAuthSlotKey (b10d) keys a connection's PreAuthLimiter slot in its
// context, where handleClient and a successful auth find it.
type preAuthSlotKey struct{}

// preAuthSlot (b10d) is a connection's PreAuthSlot, released once: at its
// successful auth or at its end, whichever comes first.
type preAuthSlot struct {
	slot     PreAuthSlot
	once     sync.Once
	released atomic.Bool
}

func (s *preAuthSlot) release() {
	s.once.Do(func() {
		s.released.Store(true)
		s.slot.Release()
	})
}

// preAuthConnContext (b10d) is the quic.Transport.ConnContext that admits each
// new connection through lim, or nil without one. quic-go cancels the context
// it passes in when the connection ends, a handshake that never completes
// included (its idle timeout ends it), which releases the slot; a successful
// auth releases it first (releasePreAuth).
func preAuthConnContext(lim PreAuthLimiter) func(context.Context, *quic.ClientInfo) (context.Context, error) {
	if lim == nil {
		return nil
	}
	return func(ctx context.Context, info *quic.ClientInfo) (context.Context, error) {
		var remote net.Addr
		if info != nil {
			remote = info.RemoteAddr
		}
		slot, ok := lim.Acquire(remote)
		if !ok {
			return nil, errPreAuthRefused
		}
		if slot == nil {
			return ctx, nil
		}
		s := &preAuthSlot{slot: slot}
		context.AfterFunc(ctx, s.release)
		return context.WithValue(ctx, preAuthSlotKey{}, s), nil
	}
}

// preAuthSlotOf (b10d) is the PreAuthLimiter slot of the connection whose
// context ctx is, nil if it holds none.
func preAuthSlotOf(ctx context.Context) *preAuthSlot {
	s, _ := ctx.Value(preAuthSlotKey{}).(*preAuthSlot)
	return s
}

// releasePreAuth (b10d) releases the PreAuthLimiter slot of the connection
// whose context ctx is, if it holds one.
func releasePreAuth(ctx context.Context) {
	if s := preAuthSlotOf(ctx); s != nil {
		s.release()
	}
}

// preAuthWindowIncrease (b10d) is the quic.Config.AllowConnectionWindowIncrease
// that keeps a connection holding an unreleased PreAuthLimiter slot at its
// initial connection window, asking next, when set, otherwise. quic-go grows
// that window when the application reads fast, so a client that has not
// authenticated could pump it up with data the server reads and drops (unknown
// frames on its control stream) and then leave that much unread in the
// streams nothing reads: request bodies whose response it holds back, its
// QPACK streams. Held, all it leaves unread stays within the initial window;
// once the slot is released, at the auth, the window grows as before. quic-go
// forbids calling into the connection or its streams from here; Context only
// reads a field.
func preAuthWindowIncrease(next func(*quic.Conn, uint64) bool) func(*quic.Conn, uint64) bool {
	return func(conn *quic.Conn, delta uint64) bool {
		if s := preAuthSlotOf(conn.Context()); s != nil && !s.released.Load() {
			return false
		}
		return next == nil || next(conn, delta)
	}
}

type Server interface {
	Serve() error
	Close() error
}

func convertToStdTLSConfig(config *Config) *tls.Config {
	var clientAuth tls.ClientAuthType
	if config.TLSConfig.ClientCAs != nil {
		clientAuth = tls.RequireAndVerifyClientCert
	} else {
		clientAuth = tls.NoClientCert
	}
	return http3.ConfigureTLSConfig(&tls.Config{
		Certificates:                config.TLSConfig.Certificates,
		GetCertificate:              config.TLSConfig.GetCertificate,
		ClientCAs:                   config.TLSConfig.ClientCAs,
		ClientAuth:                  clientAuth,
		EncryptedClientHelloKeys:    config.TLSConfig.ECHKeys,
		GetEncryptedClientHelloKeys: config.TLSConfig.GetECHKeys,
	})
}

func NewServer(config *Config) (Server, error) {
	if err := config.fill(); err != nil {
		return nil, err
	}
	tlsConfig := convertToStdTLSConfig(config)
	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     config.QUICConfig.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         config.QUICConfig.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: config.QUICConfig.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     config.QUICConfig.MaxConnectionReceiveWindow,
		MaxIdleTimeout:                 config.QUICConfig.MaxIdleTimeout,
		MaxIncomingStreams:             config.QUICConfig.MaxIncomingStreams,
		MaxIncomingUniStreams:          config.QUICConfig.MaxIncomingUniStreams,
		DisablePathMTUDiscovery:        config.QUICConfig.DisablePathMTUDiscovery,
		EnableDatagrams:                true,
		MaxDatagramFrameSize:           protocol.MaxDatagramFrameSize,
		AssumePeerMaxDatagramFrameSize: protocol.MaxDatagramFrameSize,
		DisablePathManager:             true,
	}
	if config.PreAuthLimiter != nil { // b10d
		quicConfig.AllowConnectionWindowIncrease = preAuthWindowIncrease(quicConfig.AllowConnectionWindowIncrease)
	}
	tr := &quic.Transport{
		Conn:                             config.Conn,
		DisableGSO:                       config.QUICConfig.DisableGSO,
		ConnContext:                      preAuthConnContext(config.PreAuthLimiter),   // b10d
		VerifySourceAddress:              config.VerifySourceAddress,                  // b10d
		DisableVersionNegotiationPackets: config.QUICConfig.DisableVersionNegotiation, // b10d
	}
	// A nil key means quic-go never sends stateless resets. Clients then have to
	// wait for the idle timeout to notice the server is gone, so keep them on
	// unless the user explicitly asks otherwise.
	if !config.QUICConfig.DisableStatelessReset {
		srk := config.StatelessResetKey
		if srk == nil {
			var k quic.StatelessResetKey
			if _, err := crand.Read(k[:]); err != nil {
				return nil, err
			}
			srk = &k
		}
		tr.StatelessResetKey = srk
	}
	listener, err := tr.Listen(tlsConfig, quicConfig)
	if err != nil {
		err = errors.Join(err, tr.Close(), config.Conn.Close())
		if config.Cleanup != nil {
			err = errors.Join(err, config.Cleanup.Close())
		}
		return nil, err
	}
	return &serverImpl{
		config:   config,
		tr:       tr,
		listener: listener,
	}, nil
}

type serverImpl struct {
	config   *Config
	tr       *quic.Transport
	listener *quic.Listener
}

func (s *serverImpl) Serve() error {
	for {
		conn, err := s.listener.Accept(context.Background())
		if err != nil {
			return err
		}
		go s.handleClient(conn)
	}
}

func (s *serverImpl) Close() error {
	err := errors.Join(s.listener.Close(), s.tr.Close(), s.config.Conn.Close())
	if s.config.Cleanup != nil {
		err = errors.Join(err, s.config.Cleanup.Close())
	}
	return err
}

func (s *serverImpl) handleClient(conn *quic.Conn) {
	handler := newH3sHandler(s.config, conn)
	h3s := http3.Server{
		Handler:          handler,
		StreamDispatcher: handler.ProxyStreamHijacker,
		MaxHeaderBytes:   s.config.MaxHeaderBytes, // b10d
	}
	// b10d: what ends a connection that has not authenticated: idle past
	// PreAuthTimeout (ServeHTTP holds it while a request is in flight), alive
	// past PreAuthMaxAge, or its PreAuthLimiter slot taken for a newer
	// connection. Each closes it as closePreAuth does, and a successful auth
	// stops them.
	if d := s.config.PreAuthTimeout; d > 0 {
		handler.preAuthIdle = time.AfterFunc(d, handler.closePreAuth)
		defer handler.preAuthIdle.Stop()
	}
	if d := s.config.PreAuthMaxAge; d > 0 {
		handler.preAuthAge = time.AfterFunc(d, handler.closePreAuth)
		defer handler.preAuthAge.Stop()
	}
	if slot := preAuthSlotOf(conn.Context()); slot != nil {
		slot.slot.SetCloser(func() { go handler.closePreAuth() })
	}
	err := h3s.ServeQUICConn(conn)
	// If the client is authenticated, we need to log the disconnect event
	if handler.authenticated.Load() {
		if tl := s.config.TrafficLogger; tl != nil {
			tl.LogOnlineState(handler.authID, false)
		}
		if el := s.config.EventLogger; el != nil {
			el.Disconnect(conn.RemoteAddr(), handler.authID, err)
		}
	}
	_ = conn.CloseWithError(closeErrCodeOK, "")
}

type h3sHandler struct {
	config *Config
	conn   *quic.Conn

	// b10d: authenticated is read without authMutex, by the stream dispatcher
	// and handleClient, so it is atomic; authID is written before it is set.
	authenticated atomic.Bool
	authMutex     sync.Mutex
	authID        string
	connID        uint32 // a random id for dump streams

	// b10d: the request streams open while unauthenticated
	// (PreAuthMaxStreams), and the PreAuthTimeout and PreAuthMaxAge timers,
	// set before the connection is served. preAuthMu orders the idle timer's
	// stops and restarts with preAuthRequests, the requests in flight while
	// unauthenticated.
	preAuthStreams  atomic.Int32
	preAuthIdle     *time.Timer
	preAuthAge      *time.Timer
	preAuthMu       sync.Mutex
	preAuthRequests int

	udpSM *udpSessionManager // Only set after authentication
}

func newH3sHandler(config *Config, conn *quic.Conn) *h3sHandler {
	return &h3sHandler{
		config: config,
		conn:   conn,
		connID: rand.Uint32(),
	}
}

// closePreAuth (b10d) closes the connection with HTTP/3 NO_ERROR, as an idle
// close would, unless it authenticated by then.
func (h *h3sHandler) closePreAuth() {
	if !h.authenticated.Load() {
		_ = h.conn.CloseWithError(closeErrCodeOK, "")
	}
}

// preAuthRequestStarted and preAuthRequestEnded (b10d) hold the pre-auth idle
// deadline while a request of the unauthenticated connection is in flight, an
// auth attempt and a masquerade request alike, and restart it in full when the
// last one ends: a slow response is never cut, as a keepalive timeout would
// not cut it.
func (h *h3sHandler) preAuthRequestStarted() {
	h.preAuthMu.Lock()
	defer h.preAuthMu.Unlock()
	h.preAuthRequests++
	h.preAuthIdle.Stop()
}

func (h *h3sHandler) preAuthRequestEnded() {
	h.preAuthMu.Lock()
	defer h.preAuthMu.Unlock()
	h.preAuthRequests--
	if h.preAuthRequests == 0 && !h.authenticated.Load() {
		h.preAuthIdle.Reset(h.config.PreAuthTimeout)
	}
}

// stopPreAuth (b10d) stops the pre-auth deadlines once the connection
// authenticated; preAuthMu keeps a request ending at that moment from
// restarting the idle one.
func (h *h3sHandler) stopPreAuth() {
	if h.preAuthIdle != nil {
		h.preAuthMu.Lock()
		h.preAuthIdle.Stop()
		h.preAuthMu.Unlock()
	}
	if h.preAuthAge != nil {
		h.preAuthAge.Stop()
	}
}

func (h *h3sHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// b10d: no idle deadline while this request is in flight.
	if h.preAuthIdle != nil && !h.authenticated.Load() {
		h.preAuthRequestStarted()
		defer h.preAuthRequestEnded()
	}
	if r.Method == http.MethodPost && r.Host == protocol.URLHost && r.URL.Path == protocol.URLPath {
		h.authMutex.Lock()
		defer h.authMutex.Unlock()
		if h.authenticated.Load() {
			// Already authenticated
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			return
		}
		authReq := protocol.AuthRequestFromHeader(r.Header)
		actualTx := authReq.Rx
		ok, id := h.config.Authenticator.Authenticate(h.conn.RemoteAddr(), authReq.Auth, actualTx)
		if ok {
			// b10d: hand over the way to close this connection before anything
			// of it is served (streams wait for the authenticated flag).
			if ct := h.config.ConnTracker; ct != nil {
				conn := h.conn
				ct.TrackConn(id, func() { go conn.CloseWithError(closeErrCodeTrafficLimitReached, "") })
			}
			// Set authenticated flag
			h.authID = id
			h.authenticated.Store(true)
			// b10d: no longer pre-auth: no deadlines, and its PreAuthLimiter
			// slot is free for the next connection.
			h.stopPreAuth()
			releasePreAuth(h.conn.Context())
			if h.config.IgnoreClientBandwidth {
				// Ignore client bandwidth and use the configured congestion controller.
				congestion.UseConfigured(h.conn, h.config.CongestionConfig.Type, h.config.CongestionConfig.BBRProfile)
				actualTx = 0
			} else {
				// actualTx = min(serverTx, clientRx)
				if h.config.BandwidthConfig.MaxTx > 0 && actualTx > h.config.BandwidthConfig.MaxTx {
					// We have a maxTx limit and the client is asking for more than that,
					// return and use the limit instead
					actualTx = h.config.BandwidthConfig.MaxTx
				}
				if actualTx > 0 {
					congestion.UseBrutal(h.conn, actualTx, h.config.BandwidthConfig.DisableLossCompensation)
				} else {
					// Client doesn't know its own bandwidth, use the configured congestion controller.
					congestion.UseConfigured(h.conn, h.config.CongestionConfig.Type, h.config.CongestionConfig.BBRProfile)
				}
			}
			// Auth OK, send response
			protocol.AuthResponseToHeader(w.Header(), protocol.AuthResponse{
				UDPEnabled: !h.config.DisableUDP,
				Rx:         h.config.BandwidthConfig.MaxRx,
				RxAuto:     h.config.IgnoreClientBandwidth,
			})
			w.WriteHeader(protocol.StatusAuthOK)
			// Call event logger
			if tl := h.config.TrafficLogger; tl != nil {
				tl.LogOnlineState(id, true)
			}
			if el := h.config.EventLogger; el != nil {
				el.Connect(h.conn.RemoteAddr(), id, actualTx)
			}
			// Initialize UDP session manager (if UDP is enabled)
			// We use sync.Once to make sure that only one goroutine is started,
			// as ServeHTTP may be called by multiple goroutines simultaneously
			if !h.config.DisableUDP {
				go func() {
					sm := newUDPSessionManager(
						&udpIOImpl{
							Conn:          h.conn,
							AuthID:        id,
							TrafficLogger: h.config.TrafficLogger,
							RequestHook:   h.config.RequestHook,
							Outbound:      h.config.Outbound,
							StreamLimiter: h.config.StreamLimiter,
						},
						&udpEventLoggerImpl{h.conn, id, h.config.EventLogger},
						h.config.UDPIdleTimeout,
					)
					h.udpSM = sm
					go sm.Run()
				}()
			}
		} else {
			// Auth failed, pretend to be a normal HTTP server
			h.masqHandler(w, r)
		}
	} else {
		// Not an auth request, pretend to be a normal HTTP server
		h.masqHandler(w, r)
	}
}

func (h *h3sHandler) ProxyStreamHijacker(ft http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if err != nil {
		return false, nil
	}
	if !h.authenticated.Load() {
		// b10d: http3 parks a request stream on its HEADERS read with no
		// deadline, holding a buffer of the length the client declares (up to
		// MaxHeaderBytes): cap how many one unauthenticated connection holds.
		// The stream's context ends with it, which frees its place.
		if limit := h.config.PreAuthMaxStreams; limit > 0 {
			if h.preAuthStreams.Add(1) > int32(limit) {
				h.preAuthStreams.Add(-1)
				return false, errTooManyPreAuthStreams
			}
			context.AfterFunc(stream.Context(), func() { h.preAuthStreams.Add(-1) })
		}
		return false, nil
	}

	switch ft {
	case protocol.FrameTypeTCPRequest:
		// StreamDispatcher only peeks the frame type. Consume it so ReadTCPRequest
		// starts at address length, matching pre-upgrade StreamHijacker behavior.
		if _, err := quicvarint.Read(quicvarint.NewReader(stream)); err != nil {
			return false, err
		}
		// Wraps the stream with QStream, which handles Close() properly
		qStream := &utils.QStream{Stream: stream}
		go h.handleTCPRequest(qStream)
		return true, nil
	default:
		return false, nil
	}
}

func (h *h3sHandler) handleTCPRequest(stream *utils.QStream) {
	trafficLogger := h.config.TrafficLogger
	streamStats := &StreamStats{
		AuthID:      h.authID,
		ConnID:      h.connID,
		InitialTime: time.Now(),
	}
	streamStats.State.Store(StreamStateInitial)
	streamStats.LastActiveTime.Store(time.Now())
	defer func() {
		streamStats.State.Store(StreamStateClosed)
	}()
	if trafficLogger != nil {
		trafficLogger.TraceStream(stream, streamStats)
		defer trafficLogger.UntraceStream(stream)
	}

	// Read request
	reqAddr, err := protocol.ReadTCPRequest(stream)
	if err != nil || len(reqAddr) > maxRequestAddrLength {
		// b10d: an address no name or literal can be is refused before
		// anything holds it (maxRequestAddrLength).
		_ = stream.Close()
		return
	}
	streamStats.ReqAddr.Store(reqAddr)
	// Call the hook if set
	var putback []byte
	var hooked bool
	if h.config.RequestHook != nil {
		hooked = h.config.RequestHook.Check(false, reqAddr)
		// When the hook is enabled, the server should always accept a connection
		// so that the client will send whatever request the hook wants to see.
		// This is essentially a server-side fast-open.
		if hooked {
			streamStats.State.Store(StreamStateHooking)
			_ = protocol.WriteTCPResponse(stream, true, "RequestHook enabled")
			putback, err = h.config.RequestHook.TCP(h.authID, stream, &reqAddr)
			if err != nil {
				_ = stream.Close()
				return
			}
			streamStats.setHookedReqAddr(reqAddr)
		}
	}
	// Log the event
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPRequest(h.conn.RemoteAddr(), h.authID, reqAddr)
	}
	// Per-peer stream limits (b10d): reject THIS stream only, leaving the
	// connection alive. Every admitted stream gets exactly one TCPError
	// below (its failed dial or the end of its copy) and a refused one none,
	// which is what lets a limiter count the streams open.
	if sl := h.config.StreamLimiter; sl != nil && !sl.AllowTCP(h.authID, reqAddr) {
		if !hooked {
			_ = protocol.WriteTCPResponse(stream, false, "rate limited")
		}
		_ = stream.Close()
		return
	}
	// Dial target
	streamStats.State.Store(StreamStateConnecting)
	tConn, err := h.config.Outbound.TCP(reqAddr)
	if err != nil {
		if !hooked {
			_ = protocol.WriteTCPResponse(stream, false, err.Error())
		}
		_ = stream.Close()
		// Log the error
		if h.config.EventLogger != nil {
			h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
		}
		return
	}
	if !hooked {
		_ = protocol.WriteTCPResponse(stream, true, "Connected")
	}
	streamStats.State.Store(StreamStateEstablished)
	// Put back the data if the hook requested
	if len(putback) > 0 {
		n, _ := tConn.Write(putback)
		streamStats.Tx.Add(uint64(n))
	}
	// Start proxying
	if trafficLogger != nil {
		err = copyTwoWayEx(h.authID, stream, tConn, trafficLogger, streamStats)
	} else {
		// Use the fast path if no traffic logger is set
		err = copyTwoWay(stream, tConn)
	}
	if h.config.EventLogger != nil {
		h.config.EventLogger.TCPError(h.conn.RemoteAddr(), h.authID, reqAddr, err)
	}
	// Cleanup
	_ = tConn.Close()
	_ = stream.Close()
	// Disconnect the client if TrafficLogger requested
	if err == errDisconnect {
		_ = h.conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
	}
}

func (h *h3sHandler) masqHandler(w http.ResponseWriter, r *http.Request) {
	if h.config.MasqHandler != nil {
		h.config.MasqHandler.ServeHTTP(w, r)
	} else {
		// Return 404 for everything
		http.NotFound(w, r)
	}
}

// udpIOImpl is the IO implementation for udpSessionManager with TrafficLogger support
type udpIOImpl struct {
	Conn          *quic.Conn
	AuthID        string
	TrafficLogger TrafficLogger
	RequestHook   RequestHook
	Outbound      Outbound
	StreamLimiter StreamLimiter // b10d: per-peer new-UDP-session rate gate

	senders atomic.Int32 // b10d: SendMessage calls in progress, MaxBlockedUDPSenders
}

func (io *udpIOImpl) ReceiveMessage() (*protocol.UDPMessage, error) {
	for {
		msg, err := io.Conn.ReceiveDatagram(context.Background())
		if err != nil {
			// Connection error, this will stop the session manager
			return nil, err
		}
		udpMsg, err := protocol.ParseUDPMessage(msg)
		if err != nil {
			// Invalid message, this is fine - just wait for the next
			continue
		}
		if io.TrafficLogger != nil {
			ok := io.TrafficLogger.LogTraffic(io.AuthID, uint64(len(udpMsg.Data)), 0)
			if !ok {
				// TrafficLogger requested to disconnect the client
				_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
				return nil, errDisconnect
			}
		}
		return udpMsg, nil
	}
}

func (io *udpIOImpl) SendMessage(buf []byte, msg *protocol.UDPMessage) error {
	// b10d: MaxBlockedUDPSenders. Taken before the TrafficLogger, so a
	// datagram dropped for want of a slot costs the peer nothing.
	if io.senders.Add(1) > MaxBlockedUDPSenders {
		io.senders.Add(-1)
		return nil
	}
	defer io.senders.Add(-1)
	// b10d: a datagram too big for one QUIC datagram comes back here as
	// fragments (sendMessageAutoFrag) after its first, whole attempt was
	// charged; charging them again billed it twice against the peer's cap.
	if io.TrafficLogger != nil && msg.FragCount <= 1 {
		ok := io.TrafficLogger.LogTraffic(io.AuthID, 0, uint64(len(msg.Data)))
		if !ok {
			// TrafficLogger requested to disconnect the client
			_ = io.Conn.CloseWithError(closeErrCodeTrafficLimitReached, "")
			return errDisconnect
		}
	}
	msgN := msg.Serialize(buf)
	if msgN < 0 {
		// Message larger than buffer, silent drop
		return nil
	}
	return io.Conn.SendDatagram(buf[:msgN])
}

func (io *udpIOImpl) Hook(packets [][]byte, reqAddr *string) (bool, error) {
	if io.RequestHook != nil && io.RequestHook.Check(true, *reqAddr) {
		return io.RequestHook.UDP(io.AuthID, packets, reqAddr)
	} else {
		return true, nil
	}
}

func (io *udpIOImpl) UDP(reqAddr string) (UDPConn, error) {
	// Per-peer new-session rate limit (b10d): reject this NEW UDP session
	// only — dialFunc returns the error, so the session is never created
	// and the datagram is dropped, leaving the connection alive.
	if io.StreamLimiter != nil && !io.StreamLimiter.AllowUDP(io.AuthID, reqAddr) {
		return nil, errUDPSessionLimited
	}
	return io.Outbound.UDP(reqAddr)
}

func (io *udpIOImpl) CheckUDP(reqAddr string) error {
	// b10d: checkAddr asks only about an address the session has no verdict
	// for, so this is the session's new destination: the limiter caps them
	// per peer, as the kernel caps the new flows of a WireGuard peer. Asked
	// before the Outbound, so a refused one costs no routing probe.
	if io.StreamLimiter != nil && !io.StreamLimiter.AllowUDPDest(io.AuthID, reqAddr) {
		return errUDPDestLimited
	}
	return io.Outbound.CheckUDP(reqAddr)
}

type udpEventLoggerImpl struct {
	Conn        *quic.Conn
	AuthID      string
	EventLogger EventLogger
}

func (l *udpEventLoggerImpl) New(sessionID uint32, reqAddr string) {
	if l.EventLogger != nil {
		l.EventLogger.UDPRequest(l.Conn.RemoteAddr(), l.AuthID, sessionID, reqAddr)
	}
}

func (l *udpEventLoggerImpl) Close(sessionID uint32, err error) {
	if l.EventLogger != nil {
		l.EventLogger.UDPError(l.Conn.RemoteAddr(), l.AuthID, sessionID, err)
	}
}
