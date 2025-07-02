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
	"time"
)

// Diffie-Hellman MODP-2048 parameters (RFC 3526)
var dhModp2048P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF", 16)
var dhModp2048G = big.NewInt(2)

// ASN.1 structure for IKE messages
type IKEHeader struct {
	InitiatorSPI *big.Int `asn1:"tag:0"`
	ResponderSPI *big.Int `asn1:"tag:1"`
	NextPayload  int      `asn1:"tag:2"`
	Version      int      `asn1:"tag:3"`
	ExchangeType int      `asn1:"tag:4"`
	Flags        int      `asn1:"tag:5"`
	MessageID    *big.Int `asn1:"tag:6"`
	Length       *big.Int `asn1:"tag:7"`
}

type SAPayload struct {
	ProposalNum   int
	ProtocolID    int
	SPISize       int
	NumTransforms int
	EncryptionAlg asn1.ObjectIdentifier
	IntegrityAlg  asn1.ObjectIdentifier
	DHGroup       asn1.ObjectIdentifier
}

type KEPayload struct {
	DHGroup   asn1.ObjectIdentifier
	PublicKey []byte
}

type NoncePayload struct {
	Data []byte
}

type CertPayload struct {
	CertData []byte
}

type IKEMessage struct {
	Header      IKEHeader
	SAPayload   SAPayload    `asn1:"optional,tag:1"`
	KEPayload   KEPayload    `asn1:"optional,tag:2"`
	Nonce       NoncePayload `asn1:"optional,tag:3"`
	Certificate CertPayload  `asn1:"optional,tag:4"`
}

// Object identifiers for algorithms
var (
	oidAES256CBC  = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidHMACSHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidMODP2048   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 8, 1, 2}
)

// IPSec Initiator
type IPSecInitiator struct {
	LocalIP      string
	RemoteIP     string
	LocalPort    int
	RemotePort   int
	conn         net.PacketConn
	remoteAddr   net.Addr
	certificate  *x509.Certificate
	privateKey   interface{}
	dhPrivateKey *big.Int
	dhPublicKey  *big.Int
	sharedSecret *big.Int
	spi          *big.Int
}

func (i *IPSecInitiator) LoadCertificate(certPath, keyPath string) error {
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

	i.certificate = cert
	i.privateKey = privateKey

	log.Printf("Loaded certificate: Subject=%s, Issuer=%s", cert.Subject, cert.Issuer)
	return nil
}

func (i *IPSecInitiator) generateDHKeyPair() error {
	// Generate private key (random number)
	privateKey, err := rand.Int(rand.Reader, dhModp2048P)
	if err != nil {
		return fmt.Errorf("failed to generate DH private key: %v", err)
	}

	// Calculate public key: g^private mod p
	publicKey := new(big.Int).Exp(dhModp2048G, privateKey, dhModp2048P)

	i.dhPrivateKey = privateKey
	i.dhPublicKey = publicKey

	log.Printf("Generated DH key pair: PublicKey length=%d bits", publicKey.BitLen())
	return nil
}

func (i *IPSecInitiator) computeSharedSecret(responderPublicKey *big.Int) {
	// Compute shared secret: peer_public^private mod p
	i.sharedSecret = new(big.Int).Exp(responderPublicKey, i.dhPrivateKey, dhModp2048P)
	log.Printf("Computed DH shared secret: length=%d bits", i.sharedSecret.BitLen())
}

func (i *IPSecInitiator) Connect() error {
	var addr string
	if net.ParseIP(i.RemoteIP).To4() == nil {
		// IPv6 address
		addr = fmt.Sprintf("[%s]:%d", i.RemoteIP, i.RemotePort)
	} else {
		// IPv4 address
		addr = fmt.Sprintf("%s:%d", i.RemoteIP, i.RemotePort)
	}

	// Use UDP instead of TCP
	conn, err := net.ListenPacket("udp", fmt.Sprintf(":%d", i.LocalPort))
	if err != nil {
		return fmt.Errorf("failed to create UDP socket: %v", err)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to resolve remote address: %v", err)
	}

	i.conn = conn
	i.remoteAddr = remoteAddr
	log.Printf("Connected to responder at %s via UDP", addr)
	return nil
}

func (i *IPSecInitiator) StartIKEExchange() error {
	log.Println("Starting IKE Phase 1 - Main Mode")

	// Generate DH key pair
	if err := i.generateDHKeyPair(); err != nil {
		return fmt.Errorf("DH key generation failed: %v", err)
	}

	// Phase 1: IKE_SA_INIT
	if err := i.sendIKESAInit(); err != nil {
		return fmt.Errorf("IKE_SA_INIT failed: %v", err)
	}

	// Receive IKE_SA_INIT response
	if err := i.receiveIKESAInitResponse(); err != nil {
		return fmt.Errorf("IKE_SA_INIT response failed: %v", err)
	}

	// Phase 2: IKE_AUTH (with certificates)
	if err := i.sendIKEAuth(); err != nil {
		return fmt.Errorf("IKE_AUTH failed: %v", err)
	}

	// Receive IKE_AUTH response
	if err := i.receiveIKEAuthResponse(); err != nil {
		return fmt.Errorf("IKE_AUTH response failed: %v", err)
	}

	log.Println("IPSec tunnel established successfully!")
	return nil
}

func (i *IPSecInitiator) sendIKESAInit() error {
	log.Println("Sending IKE_SA_INIT request...")

	// Generate nonce
	nonce := make([]byte, 32)
	rand.Read(nonce)

	message := IKEMessage{
		Header: IKEHeader{
			InitiatorSPI: i.spi,
			ResponderSPI: big.NewInt(0), // Will be set by responder
			NextPayload:  1,
			Version:      0x20, // IKEv2
			ExchangeType: 34,   // IKE_SA_INIT
			Flags:        0x08, // Initiator flag
			MessageID:    big.NewInt(0),
			Length:       big.NewInt(0), // Will be calculated
		},
		SAPayload: SAPayload{
			ProposalNum:   1,
			ProtocolID:    1, // IKE
			SPISize:       8,
			NumTransforms: 3,
			EncryptionAlg: oidAES256CBC,
			IntegrityAlg:  oidHMACSHA256,
			DHGroup:       oidMODP2048,
		},
		KEPayload: KEPayload{
			DHGroup:   oidMODP2048,
			PublicKey: i.dhPublicKey.Bytes(),
		},
		Nonce: NoncePayload{
			Data: nonce,
		},
	}

	// Encode message using ASN.1
	data, err := asn1.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal IKE message: %v", err)
	}

	_, err = i.conn.WriteTo(data, i.remoteAddr)
	if err != nil {
		return err
	}

	log.Printf("Sent IKE_SA_INIT: SPI=%s, DH Group=MODP-2048", i.spi.Text(16))
	return nil
}

func (i *IPSecInitiator) receiveIKESAInitResponse() error {
	log.Println("Waiting for IKE_SA_INIT response...")

	buffer := make([]byte, 4096)
	n, _, err := i.conn.ReadFrom(buffer)
	if err != nil {
		return err
	}

	var response IKEMessage
	_, err = asn1.Unmarshal(buffer[:n], &response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal IKE response: %v", err)
	}

	log.Printf("Received IKE_SA_INIT response: ResponderSPI=%s", response.Header.ResponderSPI.Text(16))

	// Validate response
	if response.Header.InitiatorSPI.Cmp(i.spi) != 0 {
		return fmt.Errorf("SPI mismatch in response")
	}

	if len(response.SAPayload.EncryptionAlg) == 0 || len(response.KEPayload.PublicKey) == 0 {
		return fmt.Errorf("missing required payloads in response")
	}

	// Extract peer's DH public key and compute shared secret
	responderPublicKey := new(big.Int).SetBytes(response.KEPayload.PublicKey)
	i.computeSharedSecret(responderPublicKey)

	log.Println("Security Association established with DH key exchange")
	return nil
}

func (i *IPSecInitiator) sendIKEAuth() error {
	log.Println("Sending IKE_AUTH request with certificate...")

	// Generate nonce for authentication
	nonce := make([]byte, 32)
	rand.Read(nonce)

	message := IKEMessage{
		Header: IKEHeader{
			InitiatorSPI: i.spi,
			ResponderSPI: big.NewInt(12345), // Would be from previous exchange
			NextPayload:  1,
			Version:      0x20,
			ExchangeType: 35, // IKE_AUTH
			Flags:        0x08,
			MessageID:    big.NewInt(1),
			Length:       big.NewInt(0),
		},
		Certificate: CertPayload{
			CertData: i.certificate.Raw,
		},
		Nonce: NoncePayload{
			Data: nonce,
		},
	}

	data, err := asn1.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal IKE_AUTH message: %v", err)
	}

	_, err = i.conn.WriteTo(data, i.remoteAddr)
	if err != nil {
		return err
	}

	log.Printf("Sent IKE_AUTH with certificate: Subject=%s", i.certificate.Subject)
	return nil
}

func (i *IPSecInitiator) receiveIKEAuthResponse() error {
	log.Println("Waiting for IKE_AUTH response...")

	buffer := make([]byte, 4096)
	n, _, err := i.conn.ReadFrom(buffer)
	if err != nil {
		return err
	}

	var response IKEMessage
	_, err = asn1.Unmarshal(buffer[:n], &response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal IKE_AUTH response: %v", err)
	}

	// Validate Responder certificate if present
	if len(response.Certificate.CertData) > 0 {
		cert, err := x509.ParseCertificate(response.Certificate.CertData)
		if err != nil {
			return fmt.Errorf("failed to parse Responder certificate: %v", err)
		}
		log.Printf("Received Responder certificate: Subject=%s, Issuer=%s", cert.Subject, cert.Issuer)

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
		log.Println("Responder certificate verified successfully")
	}

	log.Println("Received IKE_AUTH response - Authentication successful!")
	return nil
}

func (i *IPSecInitiator) SendData(data []byte) error {
	log.Printf("Sending encrypted data through IPSec tunnel: %s", string(data))

	// In real implementation, data would be encrypted using shared secret
	encryptedData := fmt.Sprintf("ESP_ENCRYPTED[%s]", string(data))

	_, err := i.conn.WriteTo([]byte(encryptedData), i.remoteAddr)
	return err
}

func (i *IPSecInitiator) Close() {
	if i.conn != nil {
		i.conn.Close()
		log.Println("IPSec connection closed")
	}
}

func RunInitiator() error {
	// Generate random SPI
	spiBytes := make([]byte, 8)
	rand.Read(spiBytes)
	spi := new(big.Int).SetBytes(spiBytes)

	initiator := IPSecInitiator{
		LocalIP:    "127.0.0.1",
		RemoteIP:   "127.0.0.1",
		LocalPort:  8001,
		RemotePort: 8000,
		spi:        spi,
	}

	// Load certificate and private key
	if err := initiator.LoadCertificate("ipsec/certs/initiator-cert.pem", "ipsec/certs/initiator-key.pem"); err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	// Connect to responder
	if err := initiator.Connect(); err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer initiator.Close()

	// Start IPSec negotiation
	if err := initiator.StartIKEExchange(); err != nil {
		return fmt.Errorf("IPSec negotiation failed: %w", err)
	}

	// Send some test data
	testData := []byte("Hello from IPSec Initiator!")
	if err := initiator.SendData(testData); err != nil {
		log.Printf("Failed to send data: %v", err)
	}

	// Keep connection alive for a bit
	time.Sleep(5 * time.Second)
	return nil
}
