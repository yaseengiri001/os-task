# kvstore/1.0 — Protocol Specification

**ST5004CEM Operating Systems and Security — Task 4, deliverable 4.2(2)**

This document specifies the application protocol spoken between
`task4_combined/client` and `task4_combined/server`. It is the contract both
sides implement: anything not stated here is not guaranteed.

---

## 1. Transport

| Property | Value |
|---|---|
| Transport | TCP (`SOCK_STREAM`), IPv4 |
| Default port | 9000 |
| Encoding | US-ASCII, printable characters `0x20`–`0x7E` |
| Framing | one message per line, terminated by `\n` (a preceding `\r` is accepted and ignored) |
| Model | strict request/response — the client sends one line, the server replies with exactly one line |
| Maximum line | 512 bytes for a request; longer lines are rejected |

### 1.1 Why framing is part of the protocol

TCP provides a **byte stream**, not a message stream. It guarantees that bytes
arrive in order and uncorrupted; it guarantees nothing about how they are
grouped into `recv()` calls. Two requests sent in quick succession may arrive as
one read, and a single request may be split across several. Any implementation
that assumes "one `send()` = one `recv()`" will work on localhost and fail
across a real network.

Both sides therefore buffer incoming bytes and extract complete lines
(`recv_line()`), which is what makes `\n` a protocol-level requirement rather
than a formatting convention.

---

## 2. Message format

**Request**

```
COMMAND [argument [argument...]]\n
```

The command is matched case-sensitively. Arguments are separated by single
spaces; the final argument of `STORE` absorbs the remainder of the line, so
values may contain spaces.

**Response**

```
<status> <text>\n
```

`<status>` is a three-digit code for the program; `<text>` is for a human. The
split follows the convention used by SMTP, FTP and HTTP.

---

## 3. Status codes

| Code | Meaning | Client should |
|---|---|---|
| `200` | Success | continue |
| `331` | Authentication challenge issued | reply with `RESPONSE` |
| `400` | Bad request — malformed, unknown, or failed validation | fix the request; do not retry unchanged |
| `401` | Unauthorised — not authenticated, or credentials rejected | authenticate |
| `404` | Not found — no such key in the caller's namespace | — |
| `408` | Timeout — no request within 15 seconds | reconnect |
| `429` | Too many failures — connection is being closed | back off |
| `503` | Server busy — connection limit reached | retry later |
| `507` | Store full | delete something |
| `500` | Server-side error | retry later |

Codes are grouped so an unrecognised one can still be handled: `2xx` succeeded,
`3xx` needs another step, `4xx` is the client's fault, `5xx` is the server's.

---

## 4. Commands

### 4.1 Available before authentication

| Command | Response | Notes |
|---|---|---|
| `HELP` | `200 OK <command list>` | |
| `PING` | `200 PONG` | liveness check |
| `AUTH <username>` | `331 CHALLENGE <nonce>` | starts the handshake |
| `RESPONSE <digest>` | `200` / `401` / `429` | completes the handshake |
| `QUIT` | `200 BYE` | server then closes |

### 4.2 Requires an authenticated session

| Command | Response | Notes |
|---|---|---|
| `WHOAMI` | `200 OK <username>` | |
| `STORE <key> <value>` | `200 OK stored <key>` | creates or replaces |
| `FETCH <key>` | `200 OK <value>` / `404` | caller's namespace only |
| `DELETE <key>` | `200 OK deleted <key>` / `404` | |
| `LIST` | `200 OK <n> key(s): <keys>` | caller's keys only |
| `STATS` | `200 OK connections=.. active=.. peak=.. commands=..` | |

---

## 5. Authentication

### 5.1 The exchange

```
client                                server
  |                                     |
  |------------- AUTH alice ----------->|   generates a fresh 16-byte nonce
  |<-- 331 CHALLENGE 9f2c1a...  --------|
  |                                     |
  |  computes HMAC-SHA256(              |
  |     key     = password,             |
  |     message = nonce_hex)            |
  |                                     |
  |------ RESPONSE 4b8e77... ---------->|   recomputes the same HMAC and
  |                                     |   compares in constant time
  |<-- 200 OK authenticated as alice ---|
```

### 5.2 Why not simply send the password

Sending `LOGIN alice secret` has two independent flaws:

1. **Exposure.** Anyone who can observe the traffic learns the password.
2. **Replay.** An attacker who merely *records* the exchange can resend it
   later and authenticate, without ever learning the password.

Challenge-response fixes both. The password never crosses the network, and the
nonce is fresh and single-use, so a captured `RESPONSE` is worthless against any
later connection.

### 5.3 Rules

- The nonce is **consumed by the first `RESPONSE`**, whether it succeeds or
  fails. Re-authenticating requires a new `AUTH`.
- A challenge is issued for **usernames that do not exist**, and the eventual
  failure is byte-identical to a wrong password. Refusing early would let an
  attacker enumerate valid accounts.
- An unknown account still costs a full HMAC computation, so response **timing**
  cannot distinguish it either.
- Digests are compared in **constant time**. `memcmp` returns as soon as bytes
  differ, and that timing leaks how many leading bytes were correct — enough to
  recover a secret one byte at a time.
- **Three failures** on one connection close it with `429`.

### 5.4 Stated limitations

This scheme proves the client knows the password. It does **not**:

- encrypt anything after the handshake — all subsequent traffic is plaintext;
- prevent an active attacker in the middle from relaying the whole exchange;
- allow the server to store password *hashes*, because recomputing the HMAC
  requires the secret itself.

The correct remedy for all three is to run this protocol inside TLS. That is a
real limitation of the design, not an oversight, and it is recorded here rather
than glossed over.

---

## 6. Validation rules

Every field is checked against an **allow-list** before it is used. An
allow-list states what is permitted and refuses everything else, so anything the
author did not anticipate fails closed. Deny-lists are routinely bypassed with
alternative encodings.

| Field | Rule |
|---|---|
| username | 1–32 chars, `[A-Za-z0-9_-]` |
| key | 1–32 chars, `[A-Za-z0-9._-]` |
| value | 1–256 chars, printable ASCII only |
| digest | exactly 64 lowercase hex characters |
| line | at most 512 bytes |

Control characters are refused in values because they corrupt terminals and logs
and are the standard vehicle for log-injection attacks.

---

## 7. Namespacing and isolation

Every stored entry records its **owner**. Lookups match on owner *and* key
together, so a user cannot reach another user's data even by guessing the exact
key name — two users may both hold a key called `secret` and each sees only
their own.

The isolation is a property of the lookup itself rather than a separate check
that a future call site could forget.

---

## 8. Connection management

| Concern | Measure |
|---|---|
| Idle connections | 15-second receive timeout, then `408` and close |
| Unterminated flood | line capped at the buffer size, then `400` and close |
| Too many connections | capped at 32 active; further clients get `503` |
| Credential guessing | 3 failures per connection, then `429` and close |
| Peer disappearing mid-write | `SIGPIPE` ignored, so the server is not killed |
| Closing | `shutdown()` then a bounded drain, so the final reply is delivered |

The last point is subtle and worth stating. Calling `close()` while unread data
is still queued makes the kernel send `RST` rather than `FIN`, and `RST`
**discards** anything queued for transmission — so the error the server just
sent never arrives. `shutdown(SHUT_WR)` followed by draining the remaining input
avoids this. The drain is bounded, because a peer that never stops sending must
not be able to hold a thread open.

---

## 9. Worked example

```
S: 200 READY kvstore/1.0 - HELP for commands
C: PING
S: 200 PONG
C: LIST
S: 401 UNAUTHORISED authenticate first
C: AUTH alice
S: 331 CHALLENGE 9f2c1a7e4b8830d5c6e1f0a2b3948576
C: RESPONSE 4b8e77c1...  (64 hex chars)
S: 200 OK authenticated as alice
C: STORE project OS coursework
S: 200 OK stored project
C: FETCH project
S: 200 OK OS coursework
C: FETCH nosuchkey
S: 404 NOT FOUND nosuchkey
C: TRUNCATE ALL
S: 400 BAD REQUEST unknown command
C: QUIT
S: 200 BYE
```

---

## 10. Conformance testing

`./client <host> <port> demo` runs 24 automated checks covering the handshake,
every command, per-user isolation, each validation rule, rate limiting, and four
simultaneous clients. Each check asserts the **expected status code**, so a
server with no validation at all would fail rather than silently pass.

Captured output: [`outputs/task4_combined_demo.txt`](outputs/task4_combined_demo.txt).
