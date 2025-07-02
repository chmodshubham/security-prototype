package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"
)

func RunServer() error {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("./mtls/certs/server-cert.pem", "./mtls/certs/server-key.pem")
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %v", err)
	}

	// Log server certificate details
	if x509Cert, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		log.Printf("Loaded server certificate: Subject=%s, Issuer=%s",
			x509Cert.Subject, x509Cert.Issuer)
	}

	// Load CA certificate
	caCert, err := os.ReadFile("./mtls/certs/ca-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to add CA certificate to pool")
	}

	// Create TLS config with client authentication
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert, // Mutual TLS
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.2 secure cipher suites
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		PreferServerCipherSuites: true,
	}

	listener, err := tls.Listen("tcp", ":9443", config)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Println("mTLS server listening on :9443")
	log.Printf("mTLS Config: MinVersion=TLS1.2, MaxVersion=TLS1.3, ClientAuth=RequireAndVerifyClientCert")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("New mTLS connection from %s", clientAddr)

	// Log TLS connection details and verify client certificate
	if tlsConn, ok := conn.(*tls.Conn); ok {
		// Force handshake to get connection state
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("mTLS handshake failed: %v", err)
			return
		}

		state := tlsConn.ConnectionState()
		logConnectionState(state, clientAddr)

		// Optional - Verify client certificate chain
		if err := verifyAndLogClientCertificate(state, clientAddr); err != nil {
			log.Printf("Client certificate verification failed: %v", err)
			return
		}
	}

	// Handle multiple messages from client
	for {
		// Set read timeout
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		buf := make([]byte, 1024)
		n, err := conn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("Connection timeout with %s", clientAddr)
				break
			}
			if err != io.EOF {
				log.Printf("Error reading from %s: %v", clientAddr, err)
			}
			break
		}

		message := string(buf[:n])
		log.Printf("Received encrypted message from %s: %s", clientAddr, message)

		// Echo message back to client with mTLS server info
		timestamp := time.Now().Format(time.RFC3339)
		response := fmt.Sprintf("mTLS_SERVER_ECHO[%s]: %s (received at %s)",
			clientAddr, message, timestamp)

		if _, err := conn.Write([]byte(response)); err != nil {
			log.Printf("Error writing to %s: %v", clientAddr, err)
			break
		}

		log.Printf("Sent encrypted response to %s", clientAddr)
	}

	log.Printf("mTLS connection with %s closed", clientAddr)
}

func logConnectionState(state tls.ConnectionState, clientAddr string) {
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

	log.Printf("mTLS handshake completed with %s: Version=%s, CipherSuite=%s",
		clientAddr, version, cipherSuite)

	// Log certificate info
	log.Printf("Client certificates received: %d, Handshake complete: %t",
		len(state.PeerCertificates), state.HandshakeComplete)
}

// Note: This verification is redundant as TLS already verified the client cert
// This function is to show explicitly what's happening during certificate verification
func verifyAndLogClientCertificate(state tls.ConnectionState, clientAddr string) error {
	// Check if client certificate was received
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("no client certificate received from %s", clientAddr)
	}

	clientCert := state.PeerCertificates[0]
	log.Printf("Client certificate from %s: Subject=%s, Issuer=%s",
		clientAddr, clientCert.Subject, clientCert.Issuer)

	// Load CA certificate for verification
	caCert, err := os.ReadFile("./mtls/certs/ca-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to add CA certificate to pool")
	}

	// Verify client certificate chain
	opts := x509.VerifyOptions{
		Roots: caPool,
	}

	if _, err := clientCert.Verify(opts); err != nil {
		return fmt.Errorf("client certificate verification failed: %v", err)
	}

	log.Printf("Client certificate verified successfully for %s", clientAddr)
	return nil
}
