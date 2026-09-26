// Command server is a minimal TACACS+ server that supports only ASCII
// login authentication (RFC 8907 section 5.4.2). It checks credentials
// against a small in-memory user table.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"tacplus/tacacs"
)

// users is a toy in-memory credential store: username -> password.
// Replace this with a real backend (DB, LDAP, etc.) for anything real.
var users = map[string]string{
	"admin": "cisco123",
	"bob":   "password1",
}

func main() {
	addr := flag.String("addr", ":5049", "address to listen on (TACACS+ default port is 49)")
	secret := flag.String("secret", "testing123", "shared secret key (must match the client)")
	flag.Parse()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("tacacs+ server listening on %s", *addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn, *secret)
	}
}

func handleConn(conn net.Conn, secret string) {
	defer conn.Close()
	log.Printf("connection from %s", conn.RemoteAddr())

	if err := handleAuthenSession(conn, secret); err != nil {
		log.Printf("session with %s ended: %v", conn.RemoteAddr(), err)
	}
}

// handleAuthenSession runs one full ASCII-login authentication exchange:
//
//	seq 1: client -> START
//	seq 2: server -> REPLY (GETUSER)   [only if START didn't already include a username]
//	seq 3: client -> CONTINUE (username)
//	seq 4: server -> REPLY (GETPASS, NOECHO)
//	seq 5: client -> CONTINUE (password)
//	seq 6: server -> REPLY (PASS or FAIL)
func handleAuthenSession(conn net.Conn, secret string) error {
	h, body, err := tacacs.ReadPacket(conn, secret)
	if err != nil {
		return fmt.Errorf("read start: %w", err)
	}
	if h.Type != tacacs.TypeAuthen {
		return fmt.Errorf("unsupported packet type 0x%02x (only authentication is implemented)", h.Type)
	}
	start, err := tacacs.ParseAuthenStart(body)
	if err != nil {
		return fmt.Errorf("bad start packet: %w", err)
	}
	log.Printf("session=%d authen start: action=%d type=%d user=%q", h.SessionID, start.Action, start.AuthenType, start.User)

	if start.AuthenType != tacacs.AuthenTypeASCII {
		return sendReply(conn, secret, h.SessionID, h.SeqNo+1, tacacs.AuthenStatusError, 0, "only ASCII login is supported by this server")
	}

	seq := h.SeqNo
	username := start.User

	if username == "" {
		seq++
		if err := sendReply(conn, secret, h.SessionID, seq, tacacs.AuthenStatusGetUser, 0, "Username: "); err != nil {
			return err
		}
		cont, nextSeq, err := readContinue(conn, secret, seq)
		if err != nil {
			return err
		}
		seq = nextSeq
		if cont.Flags&tacacs.ContinueFlagAbort != 0 {
			return fmt.Errorf("client aborted at username prompt")
		}
		username = cont.UserMsg
	}

	seq++
	if err := sendReply(conn, secret, h.SessionID, seq, tacacs.AuthenStatusGetPass, tacacs.ReplyFlagNoEcho, "Password: "); err != nil {
		return err
	}
	cont, seq, err := readContinue(conn, secret, seq)
	if err != nil {
		return err
	}
	if cont.Flags&tacacs.ContinueFlagAbort != 0 {
		return fmt.Errorf("client aborted at password prompt")
	}
	password := cont.UserMsg

	seq++
	if pw, ok := users[username]; ok && pw == password {
		log.Printf("session=%d user %q authenticated OK", h.SessionID, username)
		return sendReply(conn, secret, h.SessionID, seq, tacacs.AuthenStatusPass, 0, "Authentication succeeded")
	}
	log.Printf("session=%d user %q authentication FAILED", h.SessionID, username)
	return sendReply(conn, secret, h.SessionID, seq, tacacs.AuthenStatusFail, 0, "Authentication failed")
}

// readContinue reads the next packet, expecting it to be a CONTINUE with
// seq_no == prevSeq+1, and returns the parsed body and that seq_no.
func readContinue(conn net.Conn, secret string, prevSeq byte) (tacacs.AuthenContinue, byte, error) {
	h, body, err := tacacs.ReadPacket(conn, secret)
	if err != nil {
		return tacacs.AuthenContinue{}, 0, fmt.Errorf("read continue: %w", err)
	}
	if h.SeqNo != prevSeq+1 {
		return tacacs.AuthenContinue{}, 0, fmt.Errorf("unexpected seq_no %d (wanted %d)", h.SeqNo, prevSeq+1)
	}
	cont, err := tacacs.ParseAuthenContinue(body)
	if err != nil {
		return tacacs.AuthenContinue{}, 0, fmt.Errorf("bad continue packet: %w", err)
	}
	return cont, h.SeqNo, nil
}

func sendReply(conn net.Conn, secret string, sessionID uint32, seq byte, status, flags byte, msg string) error {
	reply := tacacs.AuthenReply{Status: status, Flags: flags, ServerMsg: msg}
	h := tacacs.Header{
		Version:   tacacs.MajorVersion | tacacs.MinorVersionDefault,
		Type:      tacacs.TypeAuthen,
		SeqNo:     seq,
		SessionID: sessionID,
	}
	return tacacs.WritePacket(conn, h, reply.Marshal(), secret)
}
