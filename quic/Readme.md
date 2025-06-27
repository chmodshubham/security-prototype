# QUIC Client-Server Prototype in Go (TLS 1.3)

## Overview

This is a minimal QUIC-secured communication between a Go client and server using TLS 1.3. The server listens on port `:4242` using a certificate signed by a local Certificate Authority (CA). The client connects, performs a QUIC handshake (which uses TLS 1.3), sends a message, and prints the server's response. The client authenticates the server using the CA certificate.

## Libraries Used

- [lucas-clemente/quic-go](https://github.com/lucas-clemente/quic-go): A pure Go implementation of the QUIC protocol.

## Certificate Generation

- A CA certificate (`certs/ca-cert.pem`) and private key (`certs/ca-key.pem`) are generated.
- A server key and certificate signing request (CSR) are generated.
- The server CSR is signed by the CA, producing `certs/server-cert.pem`.
- The server uses `certs/server-cert.pem` and `certs/server-key.pem` to authenticate itself.
- The client loads the CA certificate (`certs/ca-cert.pem`) to verify the server's identity.

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

- QUIC always uses TLS 1.3 for encryption and authentication.
- Never use `InsecureSkipVerify: true` in production.
- Always verify server certificates and hostnames to prevent man-in-the-middle attacks.

## References

- [QUIC Protocol - Medium](https://medium.com/@chmodshubham/quic-protocol-internets-new-speed-demon-76ab51155c4c)
- [QUIC IETF](https://datatracker.ietf.org/doc/html/rfc9000)
- [quic-go documentation](https://pkg.go.dev/github.com/lucas-clemente/quic-go)
- [TLS 1.3 RFC](https://datatracker.ietf.org/doc/html/rfc8446)
