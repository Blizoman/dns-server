package dns

import (
	"bytes"
	"testing"
)

// buildQueryPacket hand-encodes a minimal DNS query packet for name/qtype,
// independent of the package's own Pack implementation, so parsing tests
// don't just check round-tripping against ourselves.
func buildQueryPacket(t *testing.T, id uint16, name string, qtype uint16) []byte {
	t.Helper()
	buf := []byte{
		byte(id >> 8), byte(id),
		0x01, 0x00, // flags: RD set
		0x00, 0x01, // QDCOUNT=1
		0x00, 0x00, // ANCOUNT=0
		0x00, 0x00, // NSCOUNT=0
		0x00, 0x00, // ARCOUNT=0
	}
	for _, label := range splitLabels(name) {
		buf = append(buf, byte(len(label)))
		buf = append(buf, label...)
	}
	buf = append(buf, 0x00)
	buf = append(buf, byte(qtype>>8), byte(qtype))
	buf = append(buf, 0x00, 0x01) // QCLASS=IN
	return buf
}

func splitLabels(name string) []string {
	var labels []string
	start := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	labels = append(labels, name[start:])
	return labels
}

func TestParse_SimpleQuery(t *testing.T) {
	packet := buildQueryPacket(t, 0x1234, "example.local", TypeA)

	msg, err := Parse(packet)
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}

	if msg.Header.ID != 0x1234 {
		t.Errorf("ID = %#x, want %#x", msg.Header.ID, 0x1234)
	}
	if msg.Header.QR {
		t.Errorf("QR = true, want false for a query")
	}
	if !msg.Header.RD {
		t.Errorf("RD = false, want true")
	}
	if len(msg.Questions) != 1 {
		t.Fatalf("len(Questions) = %d, want 1", len(msg.Questions))
	}
	q := msg.Questions[0]
	if q.Name != "example.local" {
		t.Errorf("Name = %q, want %q", q.Name, "example.local")
	}
	if q.Type != TypeA {
		t.Errorf("Type = %d, want %d", q.Type, TypeA)
	}
	if q.Class != ClassIN {
		t.Errorf("Class = %d, want %d", q.Class, ClassIN)
	}
}

func TestParse_TooShort(t *testing.T) {
	_, err := Parse([]byte{0x00, 0x01, 0x02})
	if err != ErrTooShort {
		t.Fatalf("err = %v, want ErrTooShort", err)
	}
}

func TestParse_CompressedName(t *testing.T) {
	// Header + question "a.com" (offset 12), followed by a second name that
	// is just a pointer back to offset 12, exercising name-compression
	// decoding.
	packet := []byte{
		0x00, 0x01, // ID
		0x00, 0x00, // flags
		0x00, 0x01, // QDCOUNT
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		1, 'a', 3, 'c', 'o', 'm', 0x00, // "a.com" at offset 12
		0x00, 0x01, // QTYPE
		0x00, 0x01, // QCLASS
	}
	// Pointer to offset 12 (0xC00C), used to decode a name elsewhere in the
	// same packet, e.g. inside a resource record.
	pointerOffset := len(packet)
	packet = append(packet, 0xC0, 0x0C)

	name, newOffset, err := decodeName(packet, pointerOffset)
	if err != nil {
		t.Fatalf("decodeName returned error: %v", err)
	}
	if name != "a.com" {
		t.Errorf("name = %q, want %q", name, "a.com")
	}
	if newOffset != pointerOffset+2 {
		t.Errorf("newOffset = %d, want %d", newOffset, pointerOffset+2)
	}
}

func TestPackAndParse_RoundTrip(t *testing.T) {
	msg := &Message{
		Header: Header{
			ID:    0xABCD,
			QR:    true,
			AA:    true,
			RD:    true,
			RCode: RCodeSuccess,
		},
		Questions: []Question{
			{Name: "example.local", Type: TypeA, Class: ClassIN},
		},
		Answers: []ResourceRecord{
			{
				Name:  "example.local",
				Type:  TypeA,
				Class: ClassIN,
				TTL:   60,
				RData: EncodeARecordData([4]byte{10, 0, 0, 50}),
			},
		},
	}

	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("Pack returned error: %v", err)
	}

	parsed, err := Parse(packed)
	if err != nil {
		t.Fatalf("Parse(Pack()) returned error: %v", err)
	}

	if parsed.Header.ID != msg.Header.ID {
		t.Errorf("ID = %#x, want %#x", parsed.Header.ID, msg.Header.ID)
	}
	if !parsed.Header.QR {
		t.Errorf("QR = false, want true")
	}
	if parsed.Header.ANCount != 1 {
		t.Errorf("ANCount = %d, want 1", parsed.Header.ANCount)
	}
	if len(parsed.Questions) != 1 || parsed.Questions[0].Name != "example.local" {
		t.Fatalf("Questions = %+v, want [example.local]", parsed.Questions)
	}
}

func TestEncodeName_RejectsOverlongLabel(t *testing.T) {
	longLabel := bytes.Repeat([]byte("a"), 64)
	_, err := encodeName(string(longLabel) + ".com")
	if err == nil {
		t.Fatalf("expected error for label longer than 63 bytes, got nil")
	}
}

func TestEncodeName_RootDomain(t *testing.T) {
	encoded, err := encodeName("")
	if err != nil {
		t.Fatalf("encodeName(\"\") returned error: %v", err)
	}
	if !bytes.Equal(encoded, []byte{0x00}) {
		t.Errorf("encodeName(\"\") = %v, want [0x00]", encoded)
	}
}
