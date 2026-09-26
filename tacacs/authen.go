package tacacs

import (
	"encoding/binary"
	"fmt"
)

// Authentication actions (AuthenStart.Action).
const (
	AuthenActionLogin = 0x01
)

// Authentication types (AuthenStart.AuthenType). This implementation only
// handles ASCII login.
const (
	AuthenTypeASCII = 0x01
	AuthenTypePAP   = 0x02
	AuthenTypeCHAP  = 0x03
)

// Authentication service (AuthenStart.AuthenService).
const (
	AuthenServiceLogin = 0x01
)

// Authentication reply statuses (server -> client).
const (
	AuthenStatusPass    = 0x01
	AuthenStatusFail    = 0x02
	AuthenStatusGetData = 0x03
	AuthenStatusGetUser = 0x04
	AuthenStatusGetPass = 0x05
	AuthenStatusRestart = 0x06
	AuthenStatusError   = 0x07
	AuthenStatusFollow  = 0x21
)

// Reply flags (AuthenReply.Flags).
const (
	ReplyFlagNoEcho = 0x01 // tell the client not to echo the user's input (used for passwords)
)

// Continue flags (AuthenContinue.Flags).
const (
	ContinueFlagAbort = 0x01
)

// AuthenStart is the body of the first Authentication packet (seq_no == 1),
// always sent by the client.
type AuthenStart struct {
	Action        byte
	PrivLvl       byte
	AuthenType    byte
	AuthenService byte
	User          string
	Port          string
	RemAddr       string
	Data          []byte
}

// Marshal serializes an AuthenStart body to wire format.
func (s AuthenStart) Marshal() []byte {
	b := []byte{
		s.Action, s.PrivLvl, s.AuthenType, s.AuthenService,
		byte(len(s.User)), byte(len(s.Port)), byte(len(s.RemAddr)), byte(len(s.Data)),
	}
	b = append(b, []byte(s.User)...)
	b = append(b, []byte(s.Port)...)
	b = append(b, []byte(s.RemAddr)...)
	b = append(b, s.Data...)
	return b
}

// ParseAuthenStart parses an AuthenStart body from the wire.
func ParseAuthenStart(b []byte) (AuthenStart, error) {
	if len(b) < 8 {
		return AuthenStart{}, fmt.Errorf("tacacs: authen start too short")
	}
	s := AuthenStart{Action: b[0], PrivLvl: b[1], AuthenType: b[2], AuthenService: b[3]}
	userLen, portLen, remLen, dataLen := int(b[4]), int(b[5]), int(b[6]), int(b[7])
	off := 8
	if len(b) < off+userLen+portLen+remLen+dataLen {
		return AuthenStart{}, fmt.Errorf("tacacs: authen start body truncated")
	}
	s.User = string(b[off : off+userLen])
	off += userLen
	s.Port = string(b[off : off+portLen])
	off += portLen
	s.RemAddr = string(b[off : off+remLen])
	off += remLen
	s.Data = append([]byte(nil), b[off:off+dataLen]...)
	return s, nil
}

// AuthenReply is the body of a REPLY packet, always sent by the server, in
// answer to a START or CONTINUE.
type AuthenReply struct {
	Status    byte
	Flags     byte
	ServerMsg string
	Data      []byte
}

// Marshal serializes an AuthenReply body to wire format.
func (r AuthenReply) Marshal() []byte {
	b := make([]byte, 6)
	b[0] = r.Status
	b[1] = r.Flags
	binary.BigEndian.PutUint16(b[2:4], uint16(len(r.ServerMsg)))
	binary.BigEndian.PutUint16(b[4:6], uint16(len(r.Data)))
	b = append(b, []byte(r.ServerMsg)...)
	b = append(b, r.Data...)
	return b
}

// ParseAuthenReply parses an AuthenReply body from the wire.
func ParseAuthenReply(b []byte) (AuthenReply, error) {
	if len(b) < 6 {
		return AuthenReply{}, fmt.Errorf("tacacs: authen reply too short")
	}
	r := AuthenReply{Status: b[0], Flags: b[1]}
	msgLen := int(binary.BigEndian.Uint16(b[2:4]))
	dataLen := int(binary.BigEndian.Uint16(b[4:6]))
	off := 6
	if len(b) < off+msgLen+dataLen {
		return AuthenReply{}, fmt.Errorf("tacacs: authen reply body truncated")
	}
	r.ServerMsg = string(b[off : off+msgLen])
	off += msgLen
	r.Data = append([]byte(nil), b[off:off+dataLen]...)
	return r, nil
}

// AuthenContinue is the body of a CONTINUE packet, sent by the client in
// response to a GETUSER/GETDATA/GETPASS reply.
type AuthenContinue struct {
	Flags   byte
	UserMsg string
	Data    []byte
}

// Marshal serializes an AuthenContinue body to wire format.
func (c AuthenContinue) Marshal() []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint16(b[0:2], uint16(len(c.UserMsg)))
	binary.BigEndian.PutUint16(b[2:4], uint16(len(c.Data)))
	b[4] = c.Flags
	b = append(b, []byte(c.UserMsg)...)
	b = append(b, c.Data...)
	return b
}

// ParseAuthenContinue parses an AuthenContinue body from the wire.
func ParseAuthenContinue(b []byte) (AuthenContinue, error) {
	if len(b) < 5 {
		return AuthenContinue{}, fmt.Errorf("tacacs: authen continue too short")
	}
	msgLen := int(binary.BigEndian.Uint16(b[0:2]))
	dataLen := int(binary.BigEndian.Uint16(b[2:4]))
	c := AuthenContinue{Flags: b[4]}
	off := 5
	if len(b) < off+msgLen+dataLen {
		return AuthenContinue{}, fmt.Errorf("tacacs: authen continue body truncated")
	}
	c.UserMsg = string(b[off : off+msgLen])
	off += msgLen
	c.Data = append([]byte(nil), b[off:off+dataLen]...)
	return c, nil
}
