package server

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"dnsserver/internal/config"
	"dnsserver/internal/dns"
)

// startTestServer launches a Server on an ephemeral loopback UDP port and
// returns its address plus a cleanup func that shuts it down.
func startTestServer(t *testing.T, records map[string]config.Record) *net.UDPAddr {
	t.Helper()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv := New(records, logger)

	ctx, cancel := context.WithCancel(context.Background())

	ready := make(chan struct{})
	addrCh := make(chan *net.UDPAddr, 1)
	errCh := make(chan error, 1)

	// Bind on an OS-assigned port ourselves so the test can learn the
	// address before ListenAndServe starts serving.
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	addr := conn.LocalAddr().(*net.UDPAddr)
	srv.conn = conn
	close(ready)
	addrCh <- addr

	go func() {
		errCh <- srv.serveConn(ctx, conn)
	}()

	<-ready
	t.Cleanup(func() {
		cancel()
		srv.Shutdown()
		select {
		case <-errCh:
		case <-time.After(2 * time.Second):
			t.Error("server did not shut down within timeout")
		}
	})

	return <-addrCh
}

func TestServer_ResolvesConfiguredDomain(t *testing.T) {
	records := map[string]config.Record{
		"example.local": {Domain: "example.local", IP: "10.0.0.50", TTL: 60},
	}
	addr := startTestServer(t, records)

	clientConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer clientConn.Close()

	query := &dns.Message{
		Header: dns.Header{ID: 42, RD: true},
		Questions: []dns.Question{
			{Name: "example.local", Type: dns.TypeA, Class: dns.ClassIN},
		},
	}
	queryBytes, err := query.Pack()
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}

	if _, err := clientConn.Write(queryBytes); err != nil {
		t.Fatalf("Write: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	resp, err := dns.Parse(buf[:n])
	if err != nil {
		t.Fatalf("Parse response: %v", err)
	}

	if resp.Header.ID != 42 {
		t.Errorf("response ID = %d, want 42", resp.Header.ID)
	}
	if !resp.Header.QR {
		t.Errorf("QR = false, want true (response)")
	}
	if resp.Header.RCode != dns.RCodeSuccess {
		t.Fatalf("RCode = %d, want %d", resp.Header.RCode, dns.RCodeSuccess)
	}
	if len(resp.Answers) != 1 {
		t.Fatalf("len(Answers) = %d, want 1", len(resp.Answers))
	}
	ans := resp.Answers[0]
	if ans.Name != "example.local" {
		t.Errorf("answer Name = %q, want %q", ans.Name, "example.local")
	}
	if len(ans.RData) != 4 || ans.RData[0] != 10 || ans.RData[1] != 0 || ans.RData[2] != 0 || ans.RData[3] != 50 {
		t.Errorf("answer RData = %v, want [10 0 0 50]", ans.RData)
	}
	if ans.TTL != 60 {
		t.Errorf("answer TTL = %d, want 60", ans.TTL)
	}
}

func TestServer_UnknownDomainReturnsNXDomain(t *testing.T) {
	records := map[string]config.Record{
		"example.local": {Domain: "example.local", IP: "10.0.0.50", TTL: 60},
	}
	addr := startTestServer(t, records)

	clientConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer clientConn.Close()

	query := &dns.Message{
		Header: dns.Header{ID: 7, RD: true},
		Questions: []dns.Question{
			{Name: "does-not-exist.local", Type: dns.TypeA, Class: dns.ClassIN},
		},
	}
	queryBytes, _ := query.Pack()
	if _, err := clientConn.Write(queryBytes); err != nil {
		t.Fatalf("Write: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	resp, err := dns.Parse(buf[:n])
	if err != nil {
		t.Fatalf("Parse response: %v", err)
	}
	if resp.Header.RCode != dns.RCodeNameError {
		t.Errorf("RCode = %d, want %d (NXDOMAIN)", resp.Header.RCode, dns.RCodeNameError)
	}
	if len(resp.Answers) != 0 {
		t.Errorf("len(Answers) = %d, want 0", len(resp.Answers))
	}
}

func TestServer_CaseInsensitiveLookup(t *testing.T) {
	records := map[string]config.Record{
		"example.local": {Domain: "example.local", IP: "10.0.0.50", TTL: 60},
	}
	addr := startTestServer(t, records)

	clientConn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer clientConn.Close()

	query := &dns.Message{
		Header: dns.Header{ID: 1, RD: true},
		Questions: []dns.Question{
			{Name: "EXAMPLE.LOCAL", Type: dns.TypeA, Class: dns.ClassIN},
		},
	}
	queryBytes, _ := query.Pack()
	if _, err := clientConn.Write(queryBytes); err != nil {
		t.Fatalf("Write: %v", err)
	}

	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 512)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	resp, err := dns.Parse(buf[:n])
	if err != nil {
		t.Fatalf("Parse response: %v", err)
	}
	if resp.Header.RCode != dns.RCodeSuccess || len(resp.Answers) != 1 {
		t.Fatalf("expected successful case-insensitive resolution, got RCode=%d Answers=%d", resp.Header.RCode, len(resp.Answers))
	}
}
