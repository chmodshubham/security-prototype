# TLS Client-Server Prototype in Go (CA-Signed)

## Overview

This is a minimal TLS-secured communication between a Go client and server. The server listens on port `:8443` using a certificate signed by a local Certificate Authority (CA). The client connects, performs a TLS handshake, sends a message, and prints the server's response. The client **authenticates the server using the CA certificate**, not a self-signed or directly trusted server certificate.

## Detailed Call Flow

### 1. Certificate Generation

- A CA certificate (`certs/ca-cert.pem`) and private key (`certs/ca-key.pem`) are generated.
- A server key and certificate signing request (CSR) are generated.
- The server CSR is signed by the CA, producing `certs/server-cert.pem`.
- The server uses `certs/server-cert.pem` and `certs/server-key.pem` to authenticate itself.
- The client loads the CA certificate (`certs/ca-cert.pem`) to verify the server's identity.

### 2. Server Startup

- The server loads `server/server.pem` and `server/server-key.pem`.
- It creates a `tls.Config` specifying the certificate and (optionally) the minimum TLS version (default is TLS 1.2+ in Go).
- The server listens for incoming TLS connections on `:8443`.

### 3. Client Connection

- The client loads `certs/ca-cert.pem` and adds it to a certificate pool (`x509.CertPool`).
- It creates a `tls.Config` with this pool as `RootCAs` and sets `ServerName: "localhost"` (must match the CN in the server certificate).
- The client connects to `localhost:8443` using `tls.Dial`, initiating the TLS handshake.

### 4. TLS Handshake

- **ClientHello:** The client sends a `ClientHello` message, listing supported TLS versions (Go defaults to TLS 1.2+), cipher suites, and random data.
- **ServerHello:** The server responds with a `ServerHello`, selecting the TLS version and cipher suite.
- **Certificate Exchange:** The server sends its CA-signed certificate (`server-cert.pem`) to the client.
- **Certificate Verification:** The client verifies the server's certificate against its trusted CA (`ca-cert.pem`), and checks the hostname.
- **Key Exchange:** Both parties exchange key material to derive a shared secret.
- **Finished:** Both sides confirm the handshake is complete and switch to encrypted communication.

### 5. Data Exchange

- The client sends "Hello from client" over the encrypted channel.
- The server reads the message and echoes it back.
- The client reads and prints the server's response.

---

## TLS Version Used

- **Go's default TLS version is 1.2 or higher** (TLS 1.3 if both client and server support it).
- You can enforce a minimum version in `tls.Config`:
  ```go
  MinVersion: tls.VersionTLS12,
  ```
- The actual version negotiated is visible via `conn.ConnectionState().Version`.

---

## Real-World TLS Scenario vs. This Prototype

| Aspect                       | Real-World Scenario                                                     | This Prototype                                   |
| ---------------------------- | ----------------------------------------------------------------------- | ------------------------------------------------ |
| **Certificate Authority**    | Uses certificates signed by trusted CAs (e.g., Let's Encrypt, DigiCert) | Uses a local CA to sign server certificate       |
| **Certificate Verification** | Client strictly verifies server certificate and hostname                | Client verifies server certificate via CA         |
| **Hostname Validation**      | Enforced by client                                                      | Enforced (`ServerName: "localhost"`)             |
| **Key Management**           | Secure storage, rotation, and revocation                                | Static files in project directory                |
| **TLS Version**              | Enforced minimum (usually TLS 1.2 or 1.3)                               | Defaults to Go's minimum (TLS 1.2+)              |
| **Cipher Suites**            | Restricted to strong, secure ciphers                                    | Defaults to Go's secure set                      |
| **Mutual Authentication**    | Optional, often used in high-security environments                      | Not implemented                                  |
| **Production Security**      | Hardened configs, monitoring, logging, DoS protection                   | Minimal, for educational/demo use                |

---

## How TLS Works (Simplified)

1. **Handshake:** Client and server agree on protocol version, cipher suite, and exchange keys.
2. **Authentication:** Server proves its identity with a certificate signed by a trusted CA.
3. **Encryption:** All data after the handshake is encrypted using negotiated keys.
4. **Integrity:** Each message is authenticated to prevent tampering.

---

## How to Generate CA and Server Certificates

```bash
# 1. Generate CA key and certificate
openssl genrsa -out tls/certs/ca-key.pem 4096
openssl req -x509 -new -nodes -key tls/certs/ca-key.pem -sha256 -days 3650 -out tls/certs/ca-cert.pem -subj "/CN=MyRootCA"

# 2. Generate server key and CSR
openssl genrsa -out tls/certs/server-key.pem 4096
openssl req -new -key tls/certs/server-key.pem -out tls/certs/server.csr -config tls/server-openssl.cnf

# 3. Sign server CSR with CA
openssl x509 -req -in tls/certs/server.csr -CA tls/certs/ca-cert.pem -CAkey tls/certs/ca-key.pem -CAcreateserial -out tls/certs/server-cert.pem -days 365 -sha256 -extfile tls/server-openssl.cnf -extensions req_ext

# 4. Clean up - optional
rm tls/certs/server.csr
rm tls/certs/ca-cert.srl
```

## Running the Prototype

1. **Generate certificates** (see above).
2. **Start the server:**
  ```bash
   go run . -mode=tls-server
  ```
3. **Run the client:**
   ```bash
   go run . -mode=tls-client
   ```

## Security Warning

- **Never use `InsecureSkipVerify: true` in production.** 
- Always verify server certificates and hostnames to prevent man-in-the-middle attacks.
- Use certificates signed by a trusted CA for real deployments.

## References

- [TLS Connection - Medium](https://medium.com/@chmodshubham/tls-ssl-connection-d6d410114c43)
- [Go crypto/tls documentation](https://pkg.go.dev/crypto/tls)
- [OpenSSL documentation](https://www.openssl.org/docs/)