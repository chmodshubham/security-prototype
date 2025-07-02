package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"time"
)

func RunServer() error {
	// Load TLS certificate and private key
	cert, err := tls.LoadX509KeyPair("./tls/certs/server-cert.pem", "./tls/certs/server-key.pem")
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}

	// Log certificate details
	if x509Cert, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		log.Printf("Loaded server certificate: Subject=%s, Issuer=%s",
			x509Cert.Subject, x509Cert.Issuer)
	}

	// Create enhanced TLS config
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
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

	// Create listener
	listener, err := tls.Listen("tcp", ":8443", config)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Println("TLS Server listening on :8443")
	log.Printf("TLS Config: MinVersion=TLS1.2, MaxVersion=TLS1.3")

	for {
		// Accept connection
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		// Handle connection in a goroutine
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	clientAddr := conn.RemoteAddr().String()
	log.Printf("New TLS connection from %s", clientAddr)

	// Log TLS connection details
	if tlsConn, ok := conn.(*tls.Conn); ok {
		// Force handshake to get connection state
		if err := tlsConn.Handshake(); err != nil {
			log.Printf("TLS handshake failed: %v", err)
			return
		}

		state := tlsConn.ConnectionState()
		logConnectionState(state, clientAddr)
	}

	// Handle multiple messages from client
	for {
		// Set read timeout
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))

		// Create buffer for reading
		buf := make([]byte, 1024)

		// Read from connection
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

		// Echo message back to client with server info
		timestamp := time.Now().Format(time.RFC3339)
		response := fmt.Sprintf("TLS_SERVER_ECHO[%s]: %s (received at %s)",
			clientAddr, message, timestamp)

		if _, err := conn.Write([]byte(response)); err != nil {
			log.Printf("Error writing to %s: %v", clientAddr, err)
			break
		}

		log.Printf("Sent encrypted response to %s", clientAddr)
	}

	log.Printf("Connection with %s closed", clientAddr)
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

	log.Printf("TLS handshake completed with %s: Version=%s, CipherSuite=%s",
		clientAddr, version, cipherSuite)

	// Log server certificate info
	log.Printf("Server certificates in chain: %d", len(state.VerifiedChains))
}
