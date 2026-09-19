// Package server implements the UDP DNS server: it listens for queries,
// resolves them against a configured set of domain -> IP records, and
// writes back DNS responses.
package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"dnsserver/internal/config"
	"dnsserver/internal/dns"
)

// maxUDPPacketSize is large enough for any query this server needs to
// parse; DNS-over-UDP messages are normally at most 512 bytes without EDNS0.
const maxUDPPacketSize = 4096

// Server resolves DNS A-record queries against a static, configured record
// set over UDP.
type Server struct {
	log     *slog.Logger
	records map[string]config.Record

	mu   sync.Mutex
	conn *net.UDPConn
	wg   sync.WaitGroup
}

// New creates a Server that will answer using the given records and log
// through logger.
func New(records map[string]config.Record, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{
		log:     logger,
		records: records,
	}
}

// ListenAndServe binds to addr (host:port) and serves DNS queries until ctx
// is canceled, at which point it stops accepting new packets, waits for
// in-flight handlers to finish, and returns.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("server: resolving %s: %w", addr, err)
	}

	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("server: listening on %s: %w", addr, err)
	}

	s.mu.Lock()
	s.conn = conn
	s.mu.Unlock()

	s.log.Info("dns server listening", "address", conn.LocalAddr().String())

	return s.serveConn(ctx, conn)
}

// serveConn runs the receive loop over an already-bound UDP connection
// until ctx is canceled or the connection is closed. It is split out from
// ListenAndServe so tests can bind an ephemeral port themselves and observe
// its address before the server starts serving.
func (s *Server) serveConn(ctx context.Context, conn *net.UDPConn) error {
	// Close the connection when the context is canceled so the blocking
	// ReadFromUDP call below returns with an error and the loop exits.
	stopWatcher := make(chan struct{})
	defer close(stopWatcher)
	go func() {
		select {
		case <-ctx.Done():
			s.log.Info("shutting down dns server")
			conn.Close()
		case <-stopWatcher:
		}
	}()

	buf := make([]byte, maxUDPPacketSize)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				break
			}
			s.log.Warn("read error", "error", err)
			continue
		}

		packet := make([]byte, n)
		copy(packet, buf[:n])

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handlePacket(packet, clientAddr)
		}()
	}

	s.wg.Wait()
	return nil
}

// Shutdown closes the listening socket, causing ListenAndServe to return
// once any in-flight handlers finish. It is safe to call this instead of
// (or in addition to) canceling the context passed to ListenAndServe.
func (s *Server) Shutdown() {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

// handlePacket parses a single query packet, resolves it, and sends back a
// response to clientAddr.
func (s *Server) handlePacket(packet []byte, clientAddr *net.UDPAddr) {
	start := time.Now()

	query, err := dns.Parse(packet)
	if err != nil {
		s.log.Warn("failed to parse query", "client", clientAddr.String(), "error", err)
		return
	}

	response := s.buildResponse(query)

	responseBytes, err := response.Pack()
	if err != nil {
		s.log.Error("failed to pack response", "client", clientAddr.String(), "error", err)
		return
	}

	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn == nil {
		return
	}

	if _, err := conn.WriteToUDP(responseBytes, clientAddr); err != nil {
		s.log.Warn("failed to write response", "client", clientAddr.String(), "error", err)
		return
	}

	question := ""
	if len(query.Questions) > 0 {
		question = query.Questions[0].Name
	}
	s.log.Info("handled query",
		"client", clientAddr.String(),
		"question", question,
		"rcode", response.Header.RCode,
		"duration", time.Since(start),
	)
}

// buildResponse resolves a parsed query against the configured records and
// builds the corresponding DNS response message.
func (s *Server) buildResponse(query *dns.Message) *dns.Message {
	response := &dns.Message{
		Header: dns.Header{
			ID:     query.Header.ID,
			QR:     true,
			Opcode: query.Header.Opcode,
			RD:     query.Header.RD,
			RA:     false,
			AA:     true,
			RCode:  dns.RCodeSuccess,
		},
		Questions: query.Questions,
	}

	if query.Header.Opcode != dns.OpcodeQuery {
		response.Header.RCode = dns.RCodeNotImplemented
		return response
	}

	if len(query.Questions) == 0 {
		response.Header.RCode = dns.RCodeFormatError
		return response
	}

	// Only the first question is answered, matching typical resolver
	// behavior: DNS packets almost always carry exactly one question.
	q := query.Questions[0]
	record, found := s.records[normalizeDomain(q.Name)]
	if !found {
		response.Header.RCode = dns.RCodeNameError
		return response
	}

	if q.Type != dns.TypeA || q.Class != dns.ClassIN {
		// The domain is known, but we hold no record of this type/class:
		// answer with success and no records, rather than claiming the
		// name doesn't exist.
		return response
	}

	ip := net.ParseIP(record.IP).To4()
	if ip == nil {
		s.log.Error("configured record has invalid IPv4 address", "domain", record.Domain, "ip", record.IP)
		response.Header.RCode = dns.RCodeServerFailure
		return response
	}

	response.Answers = []dns.ResourceRecord{
		{
			Name:  q.Name,
			Type:  dns.TypeA,
			Class: dns.ClassIN,
			TTL:   record.TTL,
			RData: dns.EncodeARecordData([4]byte{ip[0], ip[1], ip[2], ip[3]}),
		},
	}

	return response
}

func normalizeDomain(domain string) string {
	return normalizeCase(trimTrailingDot(domain))
}

func trimTrailingDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}

func normalizeCase(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
