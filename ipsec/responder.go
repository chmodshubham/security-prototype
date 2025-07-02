package ipsec

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
)

// IPSec Responder
type IPSecResponder struct {
	LocalIP        string
	LocalPort      int
	conn           net.PacketConn
	certificate    *x509.Certificate
	privateKey     interface{}
	dhPrivateKey   *big.Int
	dhPublicKey    *big.Int
	sharedSecret   *big.Int
	responderSPI   uint64
	initiatorSPI   uint64
	activeSessions map[string]*IKESession
}

type IKESession struct {
	RemoteAddr    net.Addr
	InitiatorSPI  uint64
	ResponderSPI  uint64
	SharedSecret  *big.Int
	Authenticated bool
}

func (r *IPSecResponder) LoadCertificate(certPath, keyPath string) error {
	// Load certificate
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %v", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	// Load private key
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key: %v", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse private key: %v", err)
	}

	r.certificate = cert
	r.privateKey = privateKey

	log.Printf("Loaded certificate: Subject=%s, Issuer=%s", cert.Subject, cert.Issuer)
	return nil
}

func (r *IPSecResponder) generateDHKeyPair() error {
	// Generate private key (random number)
	privateKey, err := rand.Int(rand.Reader, dhModp2048P)
	if err != nil {
		return fmt.Errorf("failed to generate DH private key: %v", err)
	}

	// Calculate public key: g^private mod p
	publicKey := new(big.Int).Exp(dhModp2048G, privateKey, dhModp2048P)

	r.dhPrivateKey = privateKey
	r.dhPublicKey = publicKey

	log.Printf("Generated DH key pair: PublicKey length=%d bits", publicKey.BitLen())
	return nil
}

func (r *IPSecResponder) computeSharedSecret(initiatorPublicKey *big.Int) *big.Int {
	// Compute shared secret: peer_public^private mod p
	r.sharedSecret = new(big.Int).Exp(initiatorPublicKey, r.dhPrivateKey, dhModp2048P)
	log.Printf("Computed DH shared secret: length=%d bits", r.sharedSecret.BitLen())
	return r.sharedSecret
}

func (r *IPSecResponder) Start() error {
	addr := fmt.Sprintf("%s:%d", r.LocalIP, r.LocalPort)

	// Use UDP instead of TCP
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}

	r.conn = conn
	log.Printf("IPSec Responder listening on %s (UDP)", addr)

	// Generate DH key pair for this session
	if err := r.generateDHKeyPair(); err != nil {
		return fmt.Errorf("failed to generate DH key pair: %v", err)
	}

	for {
		buffer := make([]byte, 4096)
		n, clientAddr, err := conn.ReadFrom(buffer)
		if err != nil {
			log.Printf("Read error: %v", err)
			continue
		}

		log.Printf("Received packet from %s", clientAddr)
		go r.handlePacket(buffer[:n], clientAddr)
	}
}

func (r *IPSecResponder) handlePacket(data []byte, clientAddr net.Addr) {
	// Parse IKE message
	var message IKEMessage

	clientKey := clientAddr.String()

	// Check if this is data transfer for an established session
	if session, exists := r.activeSessions[clientKey]; exists && session.Authenticated {
		r.handleDataTransfer(data, clientAddr)
	} else {
		_, err := asn1.Unmarshal(data, &message)
		if err != nil {
			log.Printf("Failed to parse IKE message from %s: %v", clientAddr, err)
			return
		}

		// Handle different exchange types
		switch message.Header.ExchangeType {
		case 34: // IKE_SA_INIT
			if err := r.handleIKESAInit(&message, clientAddr); err != nil {
				log.Printf("IKE_SA_INIT failed for %s: %v", clientAddr, err)
			}
		case 35: // IKE_AUTH
			if err := r.handleIKEAuth(&message, clientAddr); err != nil {
				log.Printf("IKE_AUTH failed for %s: %v", clientAddr, err)
			}
		default:
			log.Printf("Unknown exchange type %d from %s", message.Header.ExchangeType, clientAddr)

		}
	}
}

func (r *IPSecResponder) handleIKESAInit(message *IKEMessage, clientAddr net.Addr) error {
	log.Printf("Handling IKE_SA_INIT from %s", clientAddr)

	if message.SAPayload.ProposalNum == 0 || len(message.KEPayload.PublicKey) == 0 || len(message.Nonce.Data) == 0 {
		return fmt.Errorf("missing required payloads in IKE_SA_INIT")
	}

	r.initiatorSPI = message.Header.InitiatorSPI.Uint64()
	log.Printf("Received IKE_SA_INIT from SPI=%x", r.initiatorSPI)

	// Process DH key exchange
	initiatorPublicKey := new(big.Int).SetBytes(message.KEPayload.PublicKey)
	sharedSecret := r.computeSharedSecret(initiatorPublicKey)

	// Create session
	clientKey := clientAddr.String()
	r.activeSessions[clientKey] = &IKESession{
		RemoteAddr:    clientAddr,
		InitiatorSPI:  r.initiatorSPI,
		ResponderSPI:  r.responderSPI,
		SharedSecret:  sharedSecret,
		Authenticated: false,
	}

	// Send response
	return r.sendIKESAInitResponse(message, clientAddr)
}

func (r *IPSecResponder) sendIKESAInitResponse(initMessage *IKEMessage, clientAddr net.Addr) error {
	log.Println("Sending IKE_SA_INIT response...")

	// Generate our nonce
	nonce := make([]byte, 32)
	rand.Read(nonce)

	response := IKEMessage{
		Header: IKEHeader{
			InitiatorSPI: initMessage.Header.InitiatorSPI,
			ResponderSPI: big.NewInt(int64(r.responderSPI)),
			NextPayload:  1,
			Version:      0x20,
			ExchangeType: 34,   // IKE_SA_INIT
			Flags:        0x20, // Response flag
			MessageID:    big.NewInt(0),
			Length:       big.NewInt(0),
		},
		SAPayload: SAPayload{
			ProposalNum:   1,
			ProtocolID:    1,
			SPISize:       8,
			NumTransforms: 3,
			EncryptionAlg: initMessage.SAPayload.EncryptionAlg, // Accept initiator's proposal
			IntegrityAlg:  initMessage.SAPayload.IntegrityAlg,
			DHGroup:       initMessage.SAPayload.DHGroup,
		},
		KEPayload: KEPayload{
			DHGroup:   initMessage.SAPayload.DHGroup,
			PublicKey: r.dhPublicKey.Bytes(),
		},
		Nonce: NoncePayload{
			Data: nonce,
		},
	}

	data, err := asn1.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal IKE_SA_INIT response: %v", err)
	}

	_, err = r.conn.WriteTo(data, clientAddr)
	if err != nil {
		return err
	}

	log.Printf("Sent IKE_SA_INIT response: ResponderSPI=%x", r.responderSPI)
	return nil
}

func (r *IPSecResponder) handleIKEAuth(message *IKEMessage, clientAddr net.Addr) error {
	log.Printf("Handling IKE_AUTH from %s", clientAddr)

	clientKey := clientAddr.String()
	session, exists := r.activeSessions[clientKey]
	if !exists {
		return fmt.Errorf("no active session for %s", clientAddr)
	}

	// Validate initiator certificate if present
	if len(message.Certificate.CertData) > 0 {
		cert, err := x509.ParseCertificate(message.Certificate.CertData)
		if err != nil {
			return fmt.Errorf("failed to parse initiator certificate: %v", err)
		}
		log.Printf("Received initiator certificate: Subject=%s, Issuer=%s", cert.Subject, cert.Issuer)

		// Certificate verification
		roots := x509.NewCertPool()
		caCertPEM, err := os.ReadFile("ipsec/certs/ca-cert.pem")
		if err != nil {
			return fmt.Errorf("failed to read CA certificate: %v", err)
		}
		if !roots.AppendCertsFromPEM(caCertPEM) {
			return fmt.Errorf("failed to append CA certificate to pool")
		}
		opts := x509.VerifyOptions{
			Roots: roots,
		}
		if _, err := cert.Verify(opts); err != nil {
			return fmt.Errorf("responder certificate verification failed: %v", err)
		}
		log.Println("Initiator certificate verified successfully")
	}

	// Mark session as authenticated
	session.Authenticated = true

	// Send authentication response
	return r.sendIKEAuthResponse(clientAddr)
}

func (r *IPSecResponder) sendIKEAuthResponse(clientAddr net.Addr) error {
	log.Println("Sending IKE_AUTH response with certificate...")

	// Generate nonce for authentication
	nonce := make([]byte, 32)
	rand.Read(nonce)

	response := IKEMessage{
		Header: IKEHeader{
			InitiatorSPI: big.NewInt(0).SetUint64(r.initiatorSPI),
			ResponderSPI: big.NewInt(0).SetUint64(r.responderSPI),
			NextPayload:  1,
			Version:      0x20,
			ExchangeType: 35,   // IKE_AUTH
			Flags:        0x20, // Response flag
			MessageID:    big.NewInt(1),
			Length:       big.NewInt(0),
		},
		Certificate: CertPayload{
			CertData: r.certificate.Raw,
		},
		Nonce: NoncePayload{
			Data: nonce,
		},
	}

	data, err := asn1.Marshal(response)
	if err != nil {
		return fmt.Errorf("failed to marshal IKE_AUTH response: %v", err)
	}

	_, err = r.conn.WriteTo(data, clientAddr)
	if err != nil {
		return err
	}

	log.Printf("Sent IKE_AUTH response with certificate: Subject=%s", r.certificate.Subject)
	log.Printf("IPSec tunnel established with %s", clientAddr)
	return nil
}

func (r *IPSecResponder) handleDataTransfer(data []byte, clientAddr net.Addr) {
	dataStr := string(data)
	log.Printf("Received encrypted data from %s: %s", clientAddr, dataStr)

	// In real implementation, would decrypt using shared secret
	if len(dataStr) > 14 && dataStr[:14] == "ESP_ENCRYPTED[" {
		decrypted := dataStr[14 : len(dataStr)-1] // Remove ESP_ENCRYPTED[ and ]
		log.Printf("Decrypted data: %s", decrypted)
	}

	// Echo back a response
	response := fmt.Sprintf("ESP_ENCRYPTED[ACK: %s received]", dataStr)
	r.conn.WriteTo([]byte(response), clientAddr)
}

func (r *IPSecResponder) Stop() {
	if r.conn != nil {
		r.conn.Close()
		log.Println("IPSec Responder stopped")
	}

	// Clear all active sessions
	for addr := range r.activeSessions {
		log.Printf("Closed session with %s", addr)
	}
}

func RunResponder() error {
	// Generate random responder SPI
	spiBytes := make([]byte, 8)
	rand.Read(spiBytes)
	spi := new(big.Int).SetBytes(spiBytes)

	responder := IPSecResponder{
		LocalIP:        "127.0.0.1",
		LocalPort:      8000,
		responderSPI:   spi.Uint64(),
		activeSessions: make(map[string]*IKESession),
	}

	// Load certificate and private key
	if err := responder.LoadCertificate("ipsec/certs/responder-cert.pem", "ipsec/certs/responder-key.pem"); err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	// Start the responder
	if err := responder.Start(); err != nil {
		return fmt.Errorf("responder failed: %w", err)
	}
	return nil
}
