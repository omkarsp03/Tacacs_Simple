# tacplus — a minimal, hand-written TACACS+ client/server in Go

Implements just enough of TACACS+ (RFC 8907) to run an **ASCII login
authentication** exchange, with no third-party TACACS+ libraries — the
packet header, MD5 pseudo-pad body encryption, and packet bodies are all
implemented by hand in `tacacs/`.

## Layout

```
go.mod
tacacs/
  packet.go   header struct, MD5 pseudo-pad obfuscation, read/write helpers
  authen.go   Authentication START / REPLY / CONTINUE packet bodies
cmd/
  server/     TCP server: runs the ASCII login state machine, checks a
              hardcoded user table
  client/     TCP client: sends START, follows GETUSER/GETPASS prompts,
              prints PASS/FAIL
```

## What's implemented

- The 12-byte TACACS+ header (version, type, seq_no, flags, session_id, length).
- Body obfuscation: MD5(session_id + key + version + seq_no [+ previous
  hash]) repeated and XORed with the body, exactly as RFC 8907 §4.5
  describes. Same function encrypts and decrypts since XOR is its own
  inverse.
- The Authentication packet type only, ASCII login sub-flow:
  `START -> [GETUSER -> CONTINUE] -> GETPASS -> CONTINUE -> PASS|FAIL`.

## What's *not* implemented (kept out on purpose, for simplicity)

- PAP/CHAP/MSCHAP authentication, Authorization, and Accounting packet
  types (the header/framing code supports them fine — only the ASCII
  Authentication body structs are written).
- Single-connect mode (multiplexing several sessions over one TCP
  connection) — each connection here handles exactly one login.
- Terminal raw mode: the client reads the password from stdin as plain
  text (it will echo back to your screen). A real client should switch the
  terminal to raw mode while reading it.

## Build

```
go build ./...
```

## Run

Terminal 1 (server):
```
go run ./cmd/server
```
(The program uses local port 5049 by default. Port 49 is TACACS+'s registered
port and typically needs root/sudo.)

Built-in users: `admin/cisco123`, `bob/password1` (edit the `users` map in
`cmd/server/main.go`).

Terminal 2 (client):
```
go run ./cmd/client
Username: admin
Password: cisco123
Authentication succeeded
Login OK
```

You can also pass `-user admin` on the client to skip the username prompt
and go straight to the password prompt.

The `-secret` on both sides must match — it's the TACACS+ shared secret
key used to derive the encryption pad. If they don't match, the server
will fail to parse the (garbled) body and close the connection.

## Where to go from here

- Add PAP (`AuthenTypePAP`): the password arrives in the START packet's
  `Data` field instead of a follow-up CONTINUE.
- Add Authorization (`TypeAuthor`) — attribute-value pairs (AVPs) for
  things like `service=shell`, `priv-lvl=15`, `cmd=...`.
- Add Accounting (`TypeAcct`) — start/stop/watchdog records.
- Swap the in-memory `users` map for a real backend.
