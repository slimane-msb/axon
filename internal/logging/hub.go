// Package logging provides fan-out logging for L3 and L7 firewall events.
// Logs are broadcast to:
//   - stdout/stderr (structured)
//   - A configurable TCP/HTTP endpoint (JSON over TCP or HTTP POST)
//   - Internal gRPC stream subscribers
package logging

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// FirewallLog is the unified log structure (mirrors protobuf FirewallLog)
type FirewallLog struct {
	Timestamp string `json:"timestamp"`
	Interface string `json:"interface"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	FQDN      string `json:"fqdn,omitempty"`
	RuleType  string `json:"rule_type"` // explicit | tentative | shared-l7 | mode-drop
	Action    string `json:"action"`    // blocked | allowed | redirected
	SrcPort   uint32 `json:"src_port,omitempty"`
	DstPort   uint32 `json:"dst_port,omitempty"`
	Protocol  string `json:"protocol,omitempty"`
	Layer     string `json:"layer"` // L3 | L7
}

// Logger is the primary logger used by all subsystems
type Logger struct {
	mu      sync.Mutex
	level   int    // 0=debug 1=info 2=warn 3=error
	prefix  string
}

const (
	LevelDebug = 0
	LevelInfo  = 1
	LevelWarn  = 2
	LevelError = 3
)

func NewLogger(prefix string) *Logger {
	return &Logger{prefix: prefix, level: LevelInfo}
}

func (l *Logger) log(level, format string, args ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ts := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	msg := fmt.Sprintf(format, args...)
	fmt.Printf("[%s] %s [%s] %s\n", ts, level, l.prefix, msg)
}

func (l *Logger) Debugf(f string, a ...interface{}) { l.log("DEBUG", f, a...) }
func (l *Logger) Infof(f string, a ...interface{})  { l.log("INFO ", f, a...) }
func (l *Logger) Warnf(f string, a ...interface{})  { l.log("WARN ", f, a...) }
func (l *Logger) Errorf(f string, a ...interface{}) { l.log("ERROR", f, a...) }

// ─────────────────────────────────────────────
// Fan-Out Hub
// ─────────────────────────────────────────────

// Hub fans out FirewallLog events to all registered subscribers
type Hub struct {
	mu          sync.RWMutex
	subscribers map[string]chan FirewallLog
	endpoint    string // "host:port" for external TCP log sink
	endpointMu  sync.RWMutex
	logger      *Logger
	httpClient  *http.Client
}

// NewHub creates a new fan-out log hub
func NewHub(logger *Logger) *Hub {
	return &Hub{
		subscribers: make(map[string]chan FirewallLog),
		logger:      logger,
		httpClient:  &http.Client{Timeout: 2 * time.Second},
	}
}

// Subscribe registers a subscriber with a given ID, returns a channel
func (h *Hub) Subscribe(id string, bufSize int) <-chan FirewallLog {
	h.mu.Lock()
	defer h.mu.Unlock()

	ch := make(chan FirewallLog, bufSize)
	h.subscribers[id] = ch
	return ch
}

// Unsubscribe removes a subscriber
func (h *Hub) Unsubscribe(id string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if ch, ok := h.subscribers[id]; ok {
		close(ch)
		delete(h.subscribers, id)
	}
}

// Publish sends a log event to all subscribers and the external endpoint
func (h *Hub) Publish(log FirewallLog) {
	// Fan out to internal subscribers
	h.mu.RLock()
	for _, ch := range h.subscribers {
		select {
		case ch <- log:
		default:
			// Drop if subscriber is slow
		}
	}
	h.mu.RUnlock()

	// Send to external TCP endpoint
	h.endpointMu.RLock()
	ep := h.endpoint
	h.endpointMu.RUnlock()

	if ep != "" {
		go h.sendToEndpoint(ep, log)
	}
}

// SetEndpoint configures the external log endpoint
func (h *Hub) SetEndpoint(addr string) {
	h.endpointMu.Lock()
	defer h.endpointMu.Unlock()
	h.endpoint = addr
	h.logger.Infof("Log endpoint set to: %s", addr)
}

// GetEndpoint returns the current log endpoint
func (h *Hub) GetEndpoint() string {
	h.endpointMu.RLock()
	defer h.endpointMu.RUnlock()
	return h.endpoint
}

// sendToEndpoint sends a log line to the external TCP/HTTP endpoint
func (h *Hub) sendToEndpoint(addr string, log FirewallLog) {
	data, err := json.Marshal(log)
	if err != nil {
		return
	}
	data = append(data, '\n')

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		h.logger.Debugf("Log endpoint dial failed (%s): %v", addr, err)
		return
	}
	defer conn.Close()

	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, _ = conn.Write(data)
}

// ─────────────────────────────────────────────
// Log Server (TCP listener for log consumers)
// ─────────────────────────────────────────────

// Server listens on a TCP port and streams logs as JSON lines to connected clients
type Server struct {
	addr    string
	hub     *Hub
	logger  *Logger
	mu      sync.Mutex
	clients map[net.Conn]struct{}
}

// NewServer creates a log server
func NewServer(addr string, hub *Hub, logger *Logger) *Server {
	return &Server{
		addr:    addr,
		hub:     hub,
		logger:  logger,
		clients: make(map[net.Conn]struct{}),
	}
}

// GetAddr returns the server address
func (s *Server) GetAddr() string {
	return s.addr
}

// SetAddr changes the listening address (requires restart)
func (s *Server) SetAddr(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addr = addr
}

// Run starts the TCP log server
func (s *Server) Run() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.addr, err)
	}
	defer ln.Close()

	s.logger.Infof("Log server listening on %s", s.addr)

	// Subscribe to hub for broadcasting
	sub := s.hub.Subscribe("log-server", 1000)

	// Fan-out goroutine
	go func() {
		for log := range sub {
			data, err := json.Marshal(log)
			if err != nil {
				continue
			}
			data = append(data, '\n')
			s.broadcast(data)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return err
		}
		s.mu.Lock()
		s.clients[conn] = struct{}{}
		s.mu.Unlock()

		go s.handleClient(conn)
	}
}

func (s *Server) handleClient(conn net.Conn) {
	defer func() {
		conn.Close()
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
	}()

	// Send a greeting
	_, _ = fmt.Fprintf(conn, `{"server":"axon","version":"1.0.0"}`+"\n")

	// Keep alive until client disconnects (reads nothing, writes logs)
	buf := make([]byte, 1)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		_, err := conn.Read(buf)
		if err != nil {
			return
		}
	}
}

func (s *Server) broadcast(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for conn := range s.clients {
		_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Write(data); err != nil {
			conn.Close()
			delete(s.clients, conn)
		}
	}
}
