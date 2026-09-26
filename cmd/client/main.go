// Command client is a minimal interactive TACACS+ client that performs an
// ASCII login authentication exchange against the server in cmd/server.
//
// Note: for simplicity this client reads the password from stdin without
// disabling terminal echo, so it will be visible as you type it. That's
// fine for local testing; a real client should switch the terminal to raw
// mode while reading the password.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"

	"tacplus/tacacs"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:5049", "server address to dial")
	secret := flag.String("secret", "testing123", "shared secret key (must match the server)")
	user := flag.String("user", "", "username (leave empty to be prompted by the server)")
	flag.Parse()

	conn, err := net.Dial("tcp", *addr)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	sessionID := rand.Uint32()
	reader := bufio.NewReader(os.Stdin)

	start := tacacs.AuthenStart{
		Action:        tacacs.AuthenActionLogin,
		PrivLvl:       1,
		AuthenType:    tacacs.AuthenTypeASCII,
		AuthenService: tacacs.AuthenServiceLogin,
		User:          *user,
		Port:          "cli",
		RemAddr:       "127.0.0.1",
	}
	seq := byte(1)
	h := tacacs.Header{
		Version:   tacacs.MajorVersion | tacacs.MinorVersionDefault,
		Type:      tacacs.TypeAuthen,
		SeqNo:     seq,
		SessionID: sessionID,
	}
	if err := tacacs.WritePacket(conn, h, start.Marshal(), *secret); err != nil {
		log.Fatalf("send start: %v", err)
	}

	for {
		rh, body, err := tacacs.ReadPacket(conn, *secret)
		if err != nil {
			log.Fatalf("read reply: %v", err)
		}
		reply, err := tacacs.ParseAuthenReply(body)
		if err != nil {
			log.Fatalf("parse reply: %v", err)
		}

		switch reply.Status {
		case tacacs.AuthenStatusGetUser, tacacs.AuthenStatusGetData, tacacs.AuthenStatusGetPass:
			fmt.Print(reply.ServerMsg)
			line, _ := reader.ReadString('\n')
			line = strings.TrimRight(line, "\r\n")

			seq = rh.SeqNo + 1
			cont := tacacs.AuthenContinue{UserMsg: line}
			ch := tacacs.Header{
				Version:   tacacs.MajorVersion | tacacs.MinorVersionDefault,
				Type:      tacacs.TypeAuthen,
				SeqNo:     seq,
				SessionID: sessionID,
			}
			if err := tacacs.WritePacket(conn, ch, cont.Marshal(), *secret); err != nil {
				log.Fatalf("send continue: %v", err)
			}

		case tacacs.AuthenStatusPass:
			fmt.Println(reply.ServerMsg)
			fmt.Println("Login OK")
			return

		case tacacs.AuthenStatusFail:
			fmt.Println(reply.ServerMsg)
			fmt.Println("Login FAILED")
			return

		case tacacs.AuthenStatusError:
			fmt.Println("Server error:", reply.ServerMsg)
			return

		default:
			fmt.Printf("unexpected status 0x%02x: %s\n", reply.Status, reply.ServerMsg)
			return
		}
	}
}
