# mTLS Client-Server Prototype in Go (Mutual TLS, CA-Signed)

## Overview

This is a minimal **mutual TLS (mTLS)**-secured communication between a Go client and server. Both the server and client present certificates signed by a local Certificate Authority (CA). The server listens on port `:9443`. The client connects, both sides perform a TLS handshake with mutual authentication, send a message, and print the response.

## Detailed Call Flow

### 1. Certificate Generation

- A CA certificate (`certs/ca-cert.pem`) and private key (`certs/ca-key.pem`) are generated.
- Server and client certificates are signed by the CA, producing `certs/server-cert.pem` and `certs/client-cert.pem`.
- Private keys are stored as `certs/server-key.pem` and `certs/client-key.pem`.
- The server uses `certs/server-cert.pem` and `certs/server-key.pem` to authenticate itself.
- The client uses `certs/client-cert.pem` and `certs/client-key.pem` to authenticate itself.
- Both sides use the CA certificate (`certs/ca-cert.pem`) to verify each other's identity with full certificate chain validation.

### 2. Server Startup

- The server loads its certificate and key with detailed certificate logging.
- Loads the CA certificate and sets up an enhanced `tls.Config` with `ClientAuth: tls.RequireAndVerifyClientCert`.
- Configures TLS 1.2-1.3 support, secure cipher suites, and server cipher preference.
- Listens for incoming TLS connections on `:9443` with connection state monitoring.

### 3. Client Connection

- The client loads its certificate and key with certificate detail logging.
- Loads the CA certificate and sets up an enhanced `tls.Config` with mutual authentication.
- Configures matching TLS version range and cipher suites for compatibility.
- Connects to `localhost:9443` using `tls.Dial`, initiating the mTLS handshake.

### 4. mTLS Handshake

- **ClientHello:** The client sends supported TLS versions (1.2-1.3), cipher suites, and client certificate.
- **ServerHello:** The server responds with selected TLS version, cipher suite, and server certificate.
- **Mutual Certificate Exchange:** Both server and client send their CA-signed certificates.
- **Mutual Verification:** Both sides verify the peer's certificate against the CA, validate certificate chains, and check hostnames.
- **Key Exchange:** Both parties exchange key material using ECDHE for perfect forward secrecy.
- **Finished:** Both sides confirm mutual authentication success and switch to encrypted communication.

### 5. Data Exchange

- The client sends multiple test messages: "Hello from mTLS client", "Testing mutual TLS authentication", etc.
- Each message is encrypted using the negotiated cipher suite over the encrypted channel.
- The server processes each message and echoes it back with timestamp and client address information.
- Both sides handle multiple message exchanges with proper timeout management.

## TLS Configuration and Security Features

- **TLS Versions:** TLS 1.2 and TLS 1.3 support (minimum TLS 1.2 enforced)
- **Mutual Authentication:** Both client and server verify each other's certificates automatically
- **Cipher Suites:** AES-256-GCM, AES-128-GCM, ChaCha20-Poly1305 for strong encryption
- **Perfect Forward Secrecy:** ECDHE key exchange ensures session keys are ephemeral
- **Certificate Validation:** Full chain verification against trusted CA with explicit hostname checking

## Real-World mTLS Scenario vs. This Prototype

| Aspect                       | Real-World Scenario                                                          | This Prototype                                                      |
| ---------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **Certificate Authority**    | Uses certificates signed by trusted CAs (e.g., DigiCert, Let's Encrypt)      | Uses a local CA to sign both server and client certs                |
| **Certificate Verification** | Both client and server strictly verify each other's certificate and hostname | Both client and server verify each other's certificate via local CA |
| **Mutual Authentication**    | Enforced by requiring client and server certificates                         | Enforced with `RequireAndVerifyClientCert`                          |
| **Hostname Validation**      | Enforced by both parties                                                     | Enforced (`ServerName: "localhost"`) on client                      |
| **Key Management**           | Secure storage, rotation, and revocation with HSMs                          | Static files in project directory                                   |
| **TLS Version**              | TLS 1.2 minimum, TLS 1.3 preferred                                          | TLS 1.2-1.3 range with secure configuration                         |
| **Cipher Suites**            | Restricted to strong, AEAD ciphers                                          | Modern secure cipher suites (GCM, ChaCha20-Poly1305)               |
| **Certificate Transparency** | CT logs for public certificate monitoring                                   | Not implemented (local CA)                                          |
| **OCSP Stapling**            | Real-time certificate revocation checking                                   | Not implemented                                                      |
| **Production Security**      | Hardened configs, monitoring, logging, DoS protection                        | Enhanced logging and connection management                           |

## How mTLS Works (Technical)

1. **Mutual Handshake:** Both client and server negotiate TLS version, cipher suite, and exchange certificates for mutual authentication.
2. **Dual Authentication:** Both parties prove their identities with certificates signed by the trusted CA.
3. **Bidirectional Verification:** Each side validates the peer's certificate chain and hostname.
4. **Key Exchange:** Ephemeral keys are generated using ECDHE for perfect forward secrecy.
5. **Encrypted Communication:** All application data is encrypted using negotiated AEAD cipher with mutual trust.

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

- Both server and client must present valid, CA-signed certificates for connection establishment.
- TLS configuration automatically rejects connections with invalid or unverified certificates.
- Certificate verification happens at the TLS layer - additional verification functions are redundant.
- Always verify peer certificates and hostnames to prevent man-in-the-middle attacks.
- Use strong, unique keys and protect private keys with appropriate file permissions.

## References

- [Go crypto/tls documentation](https://pkg.go.dev/crypto/tls)
- [OpenSSL documentation](https://www.openssl.org/docs/)
- [Mutual TLS (mTLS) explained](https://smallstep.com/blog/everything-pki/#mutual-tls)