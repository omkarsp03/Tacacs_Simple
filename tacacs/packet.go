// Package tacacs implements just enough of the TACACS+ protocol (RFC 8907)
// to run a simple ASCII login authentication exchange between a client and
// a server, written by hand (no third-party TACACS+ libraries).
package tacacs

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"io"
)

// Packet types (header byte 2).
const (
	TypeAuthen = 0x01 // Authentication
	TypeAuthor = 0x02 // Authorization
	TypeAcct   = 0x03 // Accounting
)

// Header flags (header byte 4).
const (
	FlagUnencrypted   = 0x01 // body sent in the clear (TAC_PLUS_UNENCRYPTED_FLAG)
	FlagSingleConnect = 0x04 // TAC_PLUS_SINGLE_CONNECT_FLAG
)

// Version byte helpers. High nibble = major version (always 0xc for TACACS+),
// low nibble = minor version (0x0 default, 0x1 used for ASCII per some
// implementations; we always use the default minor version 0x0).
const (
	MajorVersion        = 0xc0
	MinorVersionDefault = 0x00
)

// Header is the fixed 12-byte TACACS+ packet header that precedes every body.
type Header struct {
	Version   byte
	Type      byte
	SeqNo     byte
	Flags     byte
	SessionID uint32
	Length    uint32
}

// Bytes serializes the header to its 12-byte wire format.
func (h Header) Bytes() []byte {
	b := make([]byte, 12)
	b[0] = h.Version
	b[1] = h.Type
	b[2] = h.SeqNo
	b[3] = h.Flags
	binary.BigEndian.PutUint32(b[4:8], h.SessionID)
	binary.BigEndian.PutUint32(b[8:12], h.Length)
	return b
}

// ParseHeader parses a 12-byte header from the wire.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < 12 {
		return Header{}, fmt.Errorf("tacacs: header too short (%d bytes)", len(b))
	}
	return Header{
		Version:   b[0],
		Type:      b[1],
		SeqNo:     b[2],
		Flags:     b[3],
		SessionID: binary.BigEndian.Uint32(b[4:8]),
		Length:    binary.BigEndian.Uint32(b[8:12]),
	}, nil
}

// pseudoPad generates the MD5-based pseudo-random pad used to obfuscate the
// body, per RFC 8907 section 4.5:
//
//	pad[0] = MD5(session_id + key + version + seq_no)
//	pad[i] = MD5(session_id + key + version + seq_no + pad[i-1])
//	pad    = pad[0] + pad[1] + pad[2] + ...  (truncated to the body length)
func pseudoPad(sessionID uint32, key string, version, seqNo byte, length int) []byte {
	var sid [4]byte
	binary.BigEndian.PutUint32(sid[:], sessionID)

	pad := make([]byte, 0, length+md5.Size)
	var prev []byte
	for len(pad) < length {
		h := md5.New()
		h.Write(sid[:])
		h.Write([]byte(key))
		h.Write([]byte{version})
		h.Write([]byte{seqNo})
		if prev != nil {
			h.Write(prev)
		}
		sum := h.Sum(nil)
		pad = append(pad, sum...)
		prev = sum
	}
	return pad[:length]
}

// Obfuscate XORs data with the MD5 pseudo pad. Because XOR is its own
// inverse, the same function both encrypts and decrypts the body. If key is
// empty, the data is returned unchanged (unencrypted mode).
func Obfuscate(data []byte, sessionID uint32, key string, version, seqNo byte) []byte {
	if key == "" {
		return data
	}
	pad := pseudoPad(sessionID, key, version, seqNo, len(data))
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ pad[i]
	}
	return out
}

// ReadPacket reads one full TACACS+ packet (header + body) from r and
// returns the header along with the deobfuscated (plaintext) body.
func ReadPacket(r io.Reader, key string) (Header, []byte, error) {
	hb := make([]byte, 12)
	if _, err := io.ReadFull(r, hb); err != nil {
		return Header{}, nil, err
	}
	h, err := ParseHeader(hb)
	if err != nil {
		return Header{}, nil, err
	}
	if h.Length > 1<<20 { // 1 MiB sanity cap against malformed/garbage length
		return Header{}, nil, fmt.Errorf("tacacs: implausible body length %d", h.Length)
	}
	body := make([]byte, h.Length)
	if _, err := io.ReadFull(r, body); err != nil {
		return Header{}, nil, err
	}
	if h.Flags&FlagUnencrypted == 0 {
		body = Obfuscate(body, h.SessionID, key, h.Version, h.SeqNo)
	}
	return h, body, nil
}

// WritePacket obfuscates body (unless key is empty, in which case the
// FlagUnencrypted bit is set instead) and writes header+body to w.
func WritePacket(w io.Writer, h Header, body []byte, key string) error {
	toSend := body
	if key != "" {
		toSend = Obfuscate(body, h.SessionID, key, h.Version, h.SeqNo)
	} else {
		h.Flags |= FlagUnencrypted
	}
	h.Length = uint32(len(toSend))
	if _, err := w.Write(h.Bytes()); err != nil {
		return err
	}
	_, err := w.Write(toSend)
	return err
}
