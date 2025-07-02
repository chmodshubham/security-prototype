# mTLS Client-Server Prototype in Go (Mutual TLS, CA-Signed)

## Overview

This is a minimal **mutual TLS (mTLS)**-secured communication between a Go client and server. Both the server and client present certificates signed by a local Certificate Authority (CA). The server listens on port `:9443`. The client connects, both sides perform a TLS handshake with mutual authentication, send a message, and print the response.

## Detailed Call Flow

### 1. Certificate Generation

- A CA certificate (`certs/ca-cert.pem`) and private key (`certs/ca-key.pem`) are generated.
- A server key and certificate signing request (CSR) are generated.
- The server CSR is signed by the CA, producing `certs/server-cert.pem`.
- A client key and CSR are generated.
- The client CSR is signed by the CA, producing `certs/client-cert.pem`.
- The server uses `certs/server-cert.pem` and `certs/server-key.pem` to authenticate itself.
- The client uses `certs/client-cert.pem` and `certs/client-key.pem` to authenticate itself.
- Both sides use the CA certificate (`certs/ca-cert.pem`) to verify each other's identity.

### 2. Server Startup

- The server loads its certificate and key.
- Loads the CA certificate and sets up a `tls.Config` with `ClientAuth: tls.RequireAndVerifyClientCert`.
- Listens for incoming TLS connections on `:9443`.

### 3. Client Connection

- The client loads its certificate and key.
- Loads the CA certificate and sets up a `tls.Config` with its own certificate and the CA as `RootCAs`.
- Connects to `localhost:9443` using `tls.Dial`, initiating the mTLS handshake.

### 4. mTLS Handshake

- **ClientHello:** The client sends a `ClientHello` message.
- **ServerHello:** The server responds with a `ServerHello`.
- **Certificate Exchange:** Both server and client send their CA-signed certificates.
- **Certificate Verification:** Both sides verify the peer's certificate against the CA and check hostnames.
- **Key Exchange:** Both parties exchange key material to derive a shared secret.
- **Finished:** Both sides confirm the handshake is complete and switch to encrypted communication.

### 5. Data Exchange

- The client sends "Hello from mTLS client" over the encrypted channel.
- The server reads the message and echoes it back.
- The client reads and prints the server's response.

## Real-World mTLS Scenario vs. This Prototype

| Aspect                       | Real-World Scenario                                                          | This Prototype                                                      |
| ---------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **Certificate Authority**    | Uses certificates signed by trusted CAs (e.g., DigiCert, Let's Encrypt)      | Uses a local CA to sign both server and client certs                |
| **Certificate Verification** | Both client and server strictly verify each other's certificate and hostname | Both client and server verify each other's certificate via local CA |
| **Mutual Authentication**    | Enforced by requiring client and server certificates                         | Enforced (client and server both present certs)                     |
| **Hostname Validation**      | Enforced by both parties                                                     | Enforced (`ServerName: "localhost"`) on client                      |
| **Key Management**           | Secure storage, rotation, and revocation                                     | Static files in project directory                                   |
| **TLS Version**              | Enforced minimum (usually TLS 1.2 or 1.3)                                    | Defaults to Go's minimum (TLS 1.2+)                                 |
| **Cipher Suites**            | Restricted to strong, secure ciphers                                         | Defaults to Go's secure set                                         |
| **Production Security**      | Hardened configs, monitoring, logging, DoS protection                        | Minimal, for educational/demo use                                   |

## How to Generate CA, Server, and Client Certificates

```bash
# 1. Generate CA key and certificate
openssl genrsa -out mtls/certs/ca-key.pem 4096
openssl req -x509 -new -nodes -key mtls/certs/ca-key.pem -sha256 -days 3650 -out mtls/certs/ca-cert.pem -subj "/CN=MyRootCA"

# 2. Generate server key and CSR
openssl genrsa -out mtls/certs/server-key.pem 4096
openssl req -new -key mtls/certs/server-key.pem -out mtls/certs/server.csr -config mtls/server-openssl.cnf

# 3. Sign server CSR with CA
openssl x509 -req -in mtls/certs/server.csr -CA mtls/certs/ca-cert.pem -CAkey mtls/certs/ca-key.pem -CAcreateserial -out mtls/certs/server-cert.pem -days 365 -sha256 -extfile mtls/server-openssl.cnf -extensions req_ext

# 4. Generate client key and CSR
openssl genrsa -out mtls/certs/client-key.pem 4096
openssl req -new -key mtls/certs/client-key.pem -out mtls/certs/client.csr -subj "/CN=mtls-client"

# 5. Sign client CSR with CA
openssl x509 -req -in mtls/certs/client.csr -CA mtls/certs/ca-cert.pem -CAkey mtls/certs/ca-key.pem -CAcreateserial -out mtls/certs/client-cert.pem -days 365 -sha256

# 6. Clean up
rm mtls/certs/server.csr mtls/certs/client.csr mtls/certs/ca-cert.srl
```

## Running the Prototype

1. **Generate certificates** (see above).
2. **Start the mTLS server:**

```bash
go run . -mode=mtls-server
```

3. **Run the mTLS client:**

```bash
go run . -mode=mtls-client
```

## Security Notes

- Both server and client must present valid, CA-signed certificates.
- Never use `InsecureSkipVerify: true` in production.
- Always verify peer certificates and hostnames to prevent man-in-the-middle attacks.
- Use strong, unique keys and protect private keys.

## References

- [Go crypto/tls documentation](https://pkg.go.dev/crypto/tls)
- [OpenSSL documentation](https://www.openssl.org/docs/)
- [Mutual TLS (mTLS) explained](https://smallstep.com/blog/everything-pki/#mutual-tls)
