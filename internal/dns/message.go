// Package dns implements a minimal subset of the DNS wire protocol (RFC 1035)
// needed to parse incoming queries and build responses, without relying on
// any third-party DNS library.
package dns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Resource record types we understand.
const (
	TypeA     uint16 = 1
	TypeNS    uint16 = 2
	TypeCNAME uint16 = 5
	TypeSOA   uint16 = 6
	TypeAAAA  uint16 = 28
)

// Resource record classes.
const (
	ClassIN uint16 = 1
)

// Response codes (RCODE).
const (
	RCodeSuccess        uint16 = 0
	RCodeFormatError    uint16 = 1
	RCodeServerFailure  uint16 = 2
	RCodeNameError      uint16 = 3 // NXDOMAIN
	RCodeNotImplemented uint16 = 4
	RCodeRefused        uint16 = 5
)

// Opcodes.
const (
	OpcodeQuery uint16 = 0
)

var (
	// ErrTooShort is returned when a packet is smaller than a valid DNS header.
	ErrTooShort = errors.New("dns: packet too short")
	// ErrMalformed is returned when a packet cannot be parsed as a valid DNS message.
	ErrMalformed = errors.New("dns: malformed packet")
)

// headerSize is the fixed size, in bytes, of a DNS message header.
const headerSize = 12

// Header represents the 12-byte DNS message header.
type Header struct {
	ID      uint16
	QR      bool // query (false) or response (true)
	Opcode  uint16
	AA      bool // authoritative answer
	TC      bool // truncated
	RD      bool // recursion desired
	RA      bool // recursion available
	RCode   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

// Question represents a single entry in the question section of a message.
type Question struct {
	Name  string // fully-qualified domain name, without a trailing dot
	Type  uint16
	Class uint16
}

// ResourceRecord represents a single entry in the answer/authority/additional
// sections of a message. RData holds the raw record-specific payload; use
// EncodeARecord to build RData for an A record.
type ResourceRecord struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	RData []byte
}

// Message represents a parsed (or to-be-built) DNS message. Only the
// question and answer sections are modeled; authority/additional records
// are not needed by this server.
type Message struct {
	Header    Header
	Questions []Question
	Answers   []ResourceRecord
}

// Parse decodes a raw DNS packet into a Message.
func Parse(data []byte) (*Message, error) {
	if len(data) < headerSize {
		return nil, ErrTooShort
	}

	msg := &Message{}
	flags := binary.BigEndian.Uint16(data[2:4])
	msg.Header = Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		QR:      flags&0x8000 != 0,
		Opcode:  (flags >> 11) & 0xF,
		AA:      flags&0x0400 != 0,
		TC:      flags&0x0200 != 0,
		RD:      flags&0x0100 != 0,
		RA:      flags&0x0080 != 0,
		RCode:   flags & 0xF,
		QDCount: binary.BigEndian.Uint16(data[4:6]),
		ANCount: binary.BigEndian.Uint16(data[6:8]),
		NSCount: binary.BigEndian.Uint16(data[8:10]),
		ARCount: binary.BigEndian.Uint16(data[10:12]),
	}

	offset := headerSize
	for i := uint16(0); i < msg.Header.QDCount; i++ {
		name, newOffset, err := decodeName(data, offset)
		if err != nil {
			return nil, err
		}
		offset = newOffset
		if offset+4 > len(data) {
			return nil, ErrTooShort
		}
		q := Question{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
		}
		offset += 4
		msg.Questions = append(msg.Questions, q)
	}

	answers, offset, err := decodeResourceRecords(data, offset, msg.Header.ANCount)
	if err != nil {
		return nil, err
	}
	msg.Answers = answers

	// The authority and additional sections are read and discarded: this
	// server never needs to act on them, whether parsing a client query
	// (which normally carries neither) or, in tests, its own response.
	if _, offset, err = decodeResourceRecords(data, offset, msg.Header.NSCount); err != nil {
		return nil, err
	}
	if _, _, err = decodeResourceRecords(data, offset, msg.Header.ARCount); err != nil {
		return nil, err
	}

	return msg, nil
}

// decodeResourceRecords decodes count consecutive resource records starting
// at offset, returning them plus the offset immediately following the last
// one.
func decodeResourceRecords(data []byte, offset int, count uint16) ([]ResourceRecord, int, error) {
	var records []ResourceRecord
	for i := uint16(0); i < count; i++ {
		name, newOffset, err := decodeName(data, offset)
		if err != nil {
			return nil, 0, err
		}
		offset = newOffset

		if offset+10 > len(data) {
			return nil, 0, ErrTooShort
		}
		rr := ResourceRecord{
			Name:  name,
			Type:  binary.BigEndian.Uint16(data[offset : offset+2]),
			Class: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
			TTL:   binary.BigEndian.Uint32(data[offset+4 : offset+8]),
		}
		rdLength := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10

		if offset+rdLength > len(data) {
			return nil, 0, ErrTooShort
		}
		rr.RData = append([]byte(nil), data[offset:offset+rdLength]...)
		offset += rdLength

		records = append(records, rr)
	}
	return records, offset, nil
}

// decodeName decodes a (possibly compressed) domain name starting at offset
// and returns the name plus the offset immediately following it.
func decodeName(data []byte, offset int) (string, int, error) {
	var labels []string
	originalOffset := offset
	jumped := false
	// Guard against pointer loops: a compressed name cannot legally require
	// more jumps than there are bytes in the packet.
	maxJumps := len(data)
	jumps := 0

	for {
		if offset >= len(data) {
			return "", 0, ErrTooShort
		}
		length := int(data[offset])

		if length == 0 {
			offset++
			break
		}

		// Compression pointer: top two bits set.
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", 0, ErrTooShort
			}
			jumps++
			if jumps > maxJumps {
				return "", 0, ErrMalformed
			}
			pointer := int(binary.BigEndian.Uint16(data[offset:offset+2]) & 0x3FFF)
			if !jumped {
				originalOffset = offset + 2
				jumped = true
			}
			offset = pointer
			continue
		}

		if length&0xC0 != 0 {
			return "", 0, ErrMalformed
		}

		offset++
		if offset+length > len(data) {
			return "", 0, ErrTooShort
		}
		labels = append(labels, string(data[offset:offset+length]))
		offset += length
	}

	if !jumped {
		originalOffset = offset
	}

	return strings.Join(labels, "."), originalOffset, nil
}

// encodeName encodes name as a sequence of length-prefixed labels terminated
// by a zero-length label. It does not use message compression.
func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	var buf []byte
	if name != "" {
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 {
				return nil, fmt.Errorf("dns: invalid label %q in name %q", label, name)
			}
			buf = append(buf, byte(len(label)))
			buf = append(buf, label...)
		}
	}
	buf = append(buf, 0)
	return buf, nil
}

// EncodeARecordData builds the 4-byte RDATA payload for an A record from an
// IPv4 address given as four octets.
func EncodeARecordData(ip [4]byte) []byte {
	return []byte{ip[0], ip[1], ip[2], ip[3]}
}

// Pack serializes the message into its wire format.
func (m *Message) Pack() ([]byte, error) {
	buf := make([]byte, headerSize)

	binary.BigEndian.PutUint16(buf[0:2], m.Header.ID)

	var flags uint16
	if m.Header.QR {
		flags |= 0x8000
	}
	flags |= (m.Header.Opcode & 0xF) << 11
	if m.Header.AA {
		flags |= 0x0400
	}
	if m.Header.TC {
		flags |= 0x0200
	}
	if m.Header.RD {
		flags |= 0x0100
	}
	if m.Header.RA {
		flags |= 0x0080
	}
	flags |= m.Header.RCode & 0xF
	binary.BigEndian.PutUint16(buf[2:4], flags)

	binary.BigEndian.PutUint16(buf[4:6], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(m.Answers)))
	binary.BigEndian.PutUint16(buf[8:10], 0)  // NSCount
	binary.BigEndian.PutUint16(buf[10:12], 0) // ARCount

	for _, q := range m.Questions {
		encoded, err := encodeName(q.Name)
		if err != nil {
			return nil, err
		}
		buf = append(buf, encoded...)
		var qbuf [4]byte
		binary.BigEndian.PutUint16(qbuf[0:2], q.Type)
		binary.BigEndian.PutUint16(qbuf[2:4], q.Class)
		buf = append(buf, qbuf[:]...)
	}

	for _, rr := range m.Answers {
		encoded, err := encodeName(rr.Name)
		if err != nil {
			return nil, err
		}
		buf = append(buf, encoded...)
		var rbuf [10]byte
		binary.BigEndian.PutUint16(rbuf[0:2], rr.Type)
		binary.BigEndian.PutUint16(rbuf[2:4], rr.Class)
		binary.BigEndian.PutUint32(rbuf[4:8], rr.TTL)
		binary.BigEndian.PutUint16(rbuf[8:10], uint16(len(rr.RData)))
		buf = append(buf, rbuf[:]...)
		buf = append(buf, rr.RData...)
	}

	return buf, nil
}
