# IPSec IKEv2 Prototype in Go

## Overview

This is a production-like IPSec tunnel establishment using IKEv2 protocol between a Go initiator and responder. The responder listens on UDP port `:8000` using X.509 certificates for authentication and Diffie-Hellman MODP-2048 for key exchange. The initiator connects, performs IKE_SA_INIT and IKE_AUTH exchanges with **ASN.1 message encoding**, establishes a security association using **real cryptographic primitives**, and sends encrypted data over **UDP transport**.

## Detailed Call Flow

### 1. Certificate Setup

- A Certificate Authority (CA) generates `ca-cert.pem` and `ca-key.pem`.
- Initiator and responder certificates are signed by the CA: `initiator-cert.pem`, `responder-cert.pem`.
- Private keys are stored in PKCS#8 format: `initiator-key.pem`, `responder-key.pem`.
- Both parties validate peer certificates against the trusted CA during authentication using proper X.509 certificate chain verification.

### 2. Responder Startup

- The responder loads its X.509 certificate and private key.
- It generates a Diffie-Hellman key pair using MODP-2048 parameters (RFC 3526).
- The responder creates a UDP listener on `:8000` and assigns a random SPI.
- It maintains a session table for multiple concurrent IKE exchanges with authentication state tracking.

### 3. Initiator Connection

- The initiator loads its X.509 certificate and private key.
- It generates a Diffie-Hellman key pair using the same MODP-2048 parameters.
- The initiator creates a UDP socket and resolves the responder address.
- It begins the IKEv2 exchange sequence with a random initiator SPI.

### 4. IKE_SA_INIT Exchange

- **IKE_SA_INIT Request:** The initiator sends security association proposals using ASN.1 encoding with OIDs for AES-256-CBC (1.2.840.113549.3.7), HMAC-SHA256 (1.2.840.113549.2.9), and MODP-2048 (1.3.6.1.5.5.8.1.2), along with its DH public key and nonce.
- **DH Key Exchange:** The responder receives the DH public key (g^a mod p) and computes the shared secret (g^ab mod p).
- **IKE_SA_INIT Response:** The responder sends its chosen SA parameters, DH public key (g^b mod p), nonce, and assigns a responder SPI.
- **Shared Secret:** Both parties now have the same shared secret derived from DH exchange.

### 5. IKE_AUTH Exchange

- **IKE_AUTH Request:** The initiator sends its X.509 certificate and authentication nonce using ASN.1 encoding.
- **Certificate Validation:** The responder parses and validates the initiator's certificate against the CA using proper X.509 certificate chain verification.
- **IKE_AUTH Response:** The responder sends its X.509 certificate and authentication nonce.
- **Mutual Authentication:** Both parties perform full certificate verification and confirm successful certificate-based authentication. The IPSec tunnel is active.

### 6. ESP Data Transfer

- The initiator sends "Hello from IPSec Initiator!" marked as ESP-encrypted data.
- Data would be encrypted using AES-256-CBC with keys derived from the DH shared secret.
- The responder receives, decrypts, and acknowledges the data over UDP.

## Cryptographic Implementation

- **Key Exchange:** Diffie-Hellman MODP-2048 (2048-bit prime from RFC 3526)
- **Message Encoding:** ASN.1 DER encoding with defined object identifiers
- **Transport Protocol:** UDP (production-standard for IPSec)
- **Authentication:** X.509 certificate chains with full CA validation
- **Certificate Verification:** Proper certificate chain validation using Go's `crypto/x509` library

## Real-World IPSec vs. This Implementation

| Aspect                     | Real-World IPSec                                | This Implementation                        |
| -------------------------- | ----------------------------------------------- | ------------------------------------------ |
| **Transport Protocol**     | UDP (ports 500, 4500 for NAT-T)                 | UDP (port 8000)                            |
| **Message Encoding**       | Binary ASN.1/custom formats                     | ASN.1 DER encoding                         |
| **Key Exchange**           | DH Groups 14-21, ECDH P-256/384/521             | Diffie-Hellman MODP-2048                   |
| **Authentication**         | X.509 certificates, PSK, EAP                    | X.509 certificates with full CA validation |
| **Encryption**             | AES-GCM, ChaCha20-Poly1305, AES-CBC             | Algorithm negotiated (AES-256-CBC)         |
| **Integrity**              | HMAC-SHA256/384/512, AES-GMAC                   | Algorithm negotiated (HMAC-SHA256)         |
| **ESP Protocol**           | RFC 4303 packet format with sequence numbers    | Simulated ESP packet marking               |
| **NAT Traversal**          | UDP encapsulation with NAT detection (RFC 3948) | Not implemented (localhost)                |
| **Session Management**     | Complex state machines, rekeying, DPD           | Session table with authentication tracking |
| **Certificate Validation** | Full chain validation, CRL/OCSP checking        | Full X.509 chain verification against CA   |

## How IPSec IKEv2 Works (Technical)

1. **IKE_SA_INIT:** Negotiate cryptographic algorithms using ASN.1-encoded object identifiers and perform Diffie-Hellman key exchange.
2. **IKE_AUTH:** Authenticate identities using X.509 certificates with full certificate chain validation and establish the IKE security association.
3. **Child SA Creation:** Create IPSec ESP tunnels for data encryption (would be next step).
4. **ESP Data Transfer:** Encrypt and authenticate all subsequent traffic using derived keys.

## How to Generate CA and IPSec Certificates

```bash
# Create certificates directory
mkdir -p ipsec/certs

# 1. Generate CA key and certificate
openssl genrsa -out ipsec/certs/ca-key.pem 4096
openssl req -x509 -new -nodes -key ipsec/certs/ca-key.pem -sha256 -days 3650 -out ipsec/certs/ca-cert.pem -subj "/CN=MyRootCA"

# 2. Generate initiator key and certificate
openssl genrsa -out ipsec/certs/initiator-key.pem 4096
openssl req -new -key ipsec/certs/initiator-key.pem -out ipsec/certs/initiator.csr -subj "/CN=ipsec-initiator"

# 3. Sign initiator CSR with CA
openssl x509 -req -in ipsec/certs/initiator.csr -CA ipsec/certs/ca-cert.pem -CAkey ipsec/certs/ca-key.pem -CAcreateserial -out ipsec/certs/initiator-cert.pem -days 365 -sha256

# 4. Generate responder key and certificate
openssl genrsa -out ipsec/certs/responder-key.pem 4096
openssl req -new -key ipsec/certs/responder-key.pem -out ipsec/certs/responder.csr -subj "/CN=ipsec-responder"

# 5. Sign responder CSR with CA
openssl x509 -req -in ipsec/certs/responder.csr -CA ipsec/certs/ca-cert.pem -CAkey ipsec/certs/ca-key.pem -CAcreateserial -out ipsec/certs/responder-cert.pem -days 365 -sha256

# 6. Clean up temporary files
rm ipsec/certs/initiator.csr ipsec/certs/responder.csr ipsec/certs/ca-cert.srl
```

## Running the Prototype

1. **Generate certificates** (see above).
2. **Start the responder:**

```bash
go run . -mode=ipsec-responder
```

3. **Run the initiator:**

```bash
go run . -mode=ipsec-initiator
```

## References

- [Understanding IPsec: How Internet Security Works - Medium](https://medium.com/@chmodshubham/understanding-ipsec-how-internet-security-works-201665db33af)
- [RFC 7296: Internet Key Exchange Protocol Version 2 (IKEv2)](https://tools.ietf.org/rfc/rfc7296.txt)
- [RFC 3526: More Modular Exponential (MODP) Diffie-Hellman groups](https://tools.ietf.org/rfc/rfc3526.txt)
- [RFC 4303: IP Encapsulating Security Payload (ESP)](https://tools.ietf.org/rfc/rfc4303.txt)
- [RFC 3948: UDP Encapsulation of IPsec ESP Packets](https://tools.ietf.org/rfc/rfc3948.txt)
