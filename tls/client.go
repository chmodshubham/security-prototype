package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

func RunClient() error {
	// Load server's CA certificate
	caCert, err := os.ReadFile("./tls/certs/ca-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}

	// Create certificate pool and add CA certificate
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to add CA certificate to pool")
	}

	// Create TLS config
	config := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost", // Must match CN in server cert
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.2 secure cipher suites
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
	}

	log.Printf("TLS Client Config: MinVersion=TLS1.2, MaxVersion=TLS1.3, ServerName=%s", config.ServerName)

	// Connect to server
	log.Println("Connecting to TLS server...")
	conn, err := tls.Dial("tcp", "localhost:8443", config)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	log.Println("TLS connection established")

	// Log TLS connection details
	if err := logHandshakeDetails(conn); err != nil {
		return err
	}

	// Send multiple messages to test the connection
	messages := []string{
		"Hello from TLS client",
		"Testing secure communication",
		"Multiple message exchange",
		"Final test message",
	}

	for i, message := range messages {
		log.Printf("Sending message %d/%d: %s", i+1, len(messages), message)

		// Send message to server
		if _, err := conn.Write([]byte(message)); err != nil {
			return fmt.Errorf("failed to send message %d: %v", i+1, err)
		}

		// Read server's response
		buf := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(10 * time.Second))

		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read response %d: %v", i+1, err)
		}

		response := string(buf[:n])
		log.Printf("Server response %d: %s", i+1, response)

		// Small delay between messages
		time.Sleep(500 * time.Millisecond)
	}

	log.Println("TLS client completed successfully")
	return nil
}

func logHandshakeDetails(conn *tls.Conn) error {
	// Force handshake completion
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("TLS handshake failed: %v", err)
	}

	state := conn.ConnectionState()

	// Log TLS version
	version := "Unknown"
	switch state.Version {
	case tls.VersionTLS10:
		version = "TLS 1.0"
	case tls.VersionTLS11:
		version = "TLS 1.1"
	case tls.VersionTLS12:
		version = "TLS 1.2"
	case tls.VersionTLS13:
		version = "TLS 1.3"
	}

	// Log cipher suite
	cipherSuite := tls.CipherSuiteName(state.CipherSuite)
	log.Printf("TLS handshake successful: Version=%s, CipherSuite=%s", version, cipherSuite)

	// Log server certificate details
	if len(state.PeerCertificates) > 0 {
		serverCert := state.PeerCertificates[0]
		log.Printf("Server certificate: Subject=%s, Issuer=%s",
			serverCert.Subject, serverCert.Issuer)

		// Verify server certificate chain
		if err := verifyServerCertificate(serverCert); err != nil {
			return fmt.Errorf("server certificate verification failed: %v", err)
		}
		log.Printf("Server certificate verified successfully")
	}

	log.Printf("Certificate chains verified: %d", len(state.VerifiedChains))
	return nil
}

func verifyServerCertificate(cert *x509.Certificate) error {
	// Load CA certificate for verification
	caCert, err := os.ReadFile("./tls/certs/ca-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to add CA certificate to pool")
	}

	// Verify certificate chain
	opts := x509.VerifyOptions{
		Roots:   caPool,
		DNSName: "localhost",
	}

	_, err = cert.Verify(opts)
	return err
}
