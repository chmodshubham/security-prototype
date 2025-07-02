# QUIC Client-Server Prototype in Go (TLS 1.3)

## Overview

This is a minimal QUIC-secured communication between a Go client and server using TLS 1.3. The server listens on port `:4242` using a certificate signed by a local Certificate Authority (CA). The client connects, performs a QUIC handshake (which uses TLS 1.3), sends a message, and prints the server's response. The client authenticates the server using the CA certificate.

## Libraries Used

- [quic-go/quic-go](https://github.com/quic-go/quic-go): A pure Go implementation of the QUIC protocol.

## Detailed Call Flow

### 1. Certificate Generation

- A CA certificate (`certs/ca-cert.pem`) and private key (`certs/ca-key.pem`) are generated.
- A server certificate is signed by the CA, producing `certs/server-cert.pem`.
- The server uses `certs/server-cert.pem` and `certs/server-key.pem` for TLS 1.3 authentication.
- The client loads the CA certificate (`certs/ca-cert.pem`) to verify the server's identity.
- **TLS 1.3 is mandatory** - QUIC cannot operate with earlier TLS versions.

### 2. Server Startup

- The server loads `server-cert.pem` and `server-key.pem`.
- It creates a `tls.Config` enforcing TLS 1.3 with ALPN protocol negotiation.
- The server configures QUIC-specific parameters: stream limits, flow control, connection migration.
- It listens for incoming QUIC connections on `:4242` over UDP transport.

### 3. Client Connection

- The client loads `ca-cert.pem` and creates a certificate pool for server verification.
- It creates matching `tls.Config` and `quic.Config` with TLS 1.3 enforcement.
- The client connects to `localhost:4242` using `quic.DialAddr`, initiating the QUIC handshake.
- **UDP-based transport** provides faster connection establishment than TCP.

### 4. QUIC Handshake

- **Initial Packet:** Client sends QUIC Initial packet with TLS 1.3 ClientHello and connection parameters.
- **Handshake Packets:** Server responds with TLS 1.3 ServerHello, certificate, and QUIC transport parameters.
- **Certificate Verification:** Client verifies server certificate against trusted CA with hostname validation.
- **Key Derivation:** Both parties derive QUIC connection keys from TLS 1.3 handshake.
- **1-RTT Complete:** Handshake completes faster than TCP+TLS with potential 0-RTT for resumed connections.

### 5. Stream Management and Data Exchange

- **Multiple Concurrent Streams:** Client opens multiple bidirectional streams simultaneously.
- **Stream Multiplexing:** All streams share the same QUIC connection without head-of-line blocking.
- **Flow Control:** Per-stream and per-connection flow control prevents buffer overflow.
- **Message Exchange:** Client sends test messages on different streams concurrently.
- **Server Processing:** Server handles each stream independently with goroutines.

---

## QUIC Features and Advantages

- **TLS 1.3 Integration:** Built-in encryption and authentication (not optional)
- **0-RTT Capability:** Resumed connections can send data immediately
- **Multiplexed Streams:** Multiple streams without head-of-line blocking
- **Connection Migration:** Connections survive IP address changes
- **Improved Congestion Control:** Better than TCP in lossy networks
- **UDP Transport:** Faster than TCP connection establishment

---

## Real-World QUIC vs. This Prototype

| Aspect                       | Real-World QUIC (HTTP/3)                                            | This Prototype                               |
| ---------------------------- | ------------------------------------------------------------------- | -------------------------------------------- |
| **Certificate Authority**    | Uses certificates from trusted public CAs (Let's Encrypt, DigiCert) | Uses a local CA to sign server certificate   |
| **Certificate Verification** | Client verifies server certificate and enforces CT policies         | Client verifies server certificate via CA    |
| **Protocol Usage**           | HTTP/3, WebTransport, custom application protocols                  | Custom echo protocol with ALPN               |
| **Connection Migration**     | Seamless handoff between networks (WiFi/Cellular)                   | Enabled but not demonstrated (localhost)     |
| **0-RTT Optimization**       | Aggressive 0-RTT for web performance                                | Supported but requires connection resumption |
| **Congestion Control**       | Advanced algorithms (BBR, Cubic variants)                           | Default QUIC-go implementation               |
| **Stream Management**        | Thousands of concurrent streams for web resources                   | Demonstration with multiple test streams     |
| **Loss Recovery**            | Sophisticated packet loss detection and recovery                    | Standard QUIC loss recovery                  |
| **Flow Control**             | Dynamic window scaling based on network conditions                  | Static window configuration                  |

---

## How QUIC Works (Technical)

1. **UDP Foundation:** Built on UDP for flexibility and performance
2. **Integrated TLS 1.3:** Encryption and authentication are mandatory and built-in
3. **Stream Multiplexing:** Multiple independent streams share one connection
4. **Connection IDs:** Connections identified by IDs, not IP:port tuples
5. **Packet-Level Encryption:** All packets except Initial are encrypted
6. **Flow Control:** Both stream-level and connection-level flow control
7. **Loss Recovery:** Sophisticated packet loss detection without TCP limitations

## How to Generate CA and Server Certificates

```bash
# 1. Generate CA key and certificate
openssl genrsa -out quic/certs/ca-key.pem 4096
openssl req -x509 -new -nodes -key quic/certs/ca-key.pem -sha256 -days 3650 -out quic/certs/ca-cert.pem -subj "/CN=MyRootCA"

# 2. Generate server key and CSR
openssl genrsa -out quic/certs/server-key.pem 4096
openssl req -new -key quic/certs/server-key.pem -out quic/certs/server.csr -config quic/server-openssl.cnf

# 3. Sign server CSR with CA
openssl x509 -req -in quic/certs/server.csr -CA quic/certs/ca-cert.pem -CAkey quic/certs/ca-key.pem -CAcreateserial -out quic/certs/server-cert.pem -days 365 -sha256 -extfile quic/server-openssl.cnf -extensions req_ext

# 4. Clean up - optional
rm quic/certs/server.csr quic/certs/ca-cert.srl
```

## Running the Prototype

1. **Generate certificates** (see above).
2. **Install dependencies:**

```bash
go get github.com/quic-go/quic-go
```

3. **Start the QUIC server:**

```bash
go run . -mode=quic-server
```

4. **Run the QUIC client:**

```bash
go run . -mode=quic-client
```

## Security Notes

- **TLS 1.3 is mandatory** - QUIC cannot operate without proper encryption
- Always verify server certificates to prevent man-in-the-middle attacks
- Use certificates signed by trusted CAs for production deployments
- Monitor connection migration to detect potential attacks

## References

- [QUIC: The Future of Internet Transport - Medium](https://medium.com/@chmodshubham/quic-protocol-internets-new-speed-demon-76ab51155c4c)
- [RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport](https://tools.ietf.org/rfc/rfc9000.txt)
- [RFC 9001: Using TLS to Secure QUIC](https://tools.ietf.org/rfc/rfc9001.txt)
- [QUIC-Go Documentation](https://pkg.go.dev/github.com/quic-go/quic-go)
- [TLS 1.3 RFC](https://datatracker.ietf.org/doc/html/rfc8446)
- [HTTP/3 Specification](https://tools.ietf.org/rfc/rfc9114.txt)
