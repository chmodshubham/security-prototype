package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"time"

	quic "github.com/quic-go/quic-go"
)

func RunServer() error {
	// Load TLS certificate and key
	cert, err := tls.LoadX509KeyPair("./quic/certs/server-cert.pem", "./quic/certs/server-key.pem")
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}

	// Log server certificate details
	if x509Cert, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		log.Printf("Loaded server certificate: Subject=%s, Issuer=%s",
			x509Cert.Subject, x509Cert.Issuer)
		log.Printf("Certificate valid from %s to %s",
			x509Cert.NotBefore.Format(time.RFC3339),
			x509Cert.NotAfter.Format(time.RFC3339))
	}

	// TLS config for QUIC (TLS 1.3 enforced)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13, // QUIC requires TLS 1.3
		MaxVersion:   tls.VersionTLS13,
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites (automatically used)
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		NextProtos: []string{"quic-echo-example"}, // ALPN for QUIC
	}

	// QUIC configuration
	quicConf := &quic.Config{
		MaxIdleTimeout:                 30 * time.Second,
		KeepAlivePeriod:                10 * time.Second,
		MaxIncomingStreams:             1000,
		MaxIncomingUniStreams:          100,
		InitialStreamReceiveWindow:     512 * 1024,      // 512 KB
		MaxStreamReceiveWindow:         2 * 1024 * 1024, // 2 MB
		InitialConnectionReceiveWindow: 1024 * 1024,     // 1 MB
		MaxConnectionReceiveWindow:     5 * 1024 * 1024, // 5 MB
	}

	listener, err := quic.ListenAddr("localhost:4242", tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("failed to start QUIC listener: %v", err)
	}
	defer listener.Close()

	log.Println("QUIC server listening on :4242")
	log.Printf("QUIC Config: TLS1.3, MaxStreams=%d, IdleTimeout=%v",
		quicConf.MaxIncomingStreams, quicConf.MaxIdleTimeout)

	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			log.Printf("Failed to accept session: %v", err)
			continue
		}

		go handleSession(sess)
	}
}

func handleSession(sess quic.Connection) {
	defer sess.CloseWithError(0, "session complete")

	remoteAddr := sess.RemoteAddr()
	log.Printf("New QUIC session from %s", remoteAddr)

	// Log connection state
	connState := sess.ConnectionState()
	logConnectionState(connState, remoteAddr.String())

	// Handle multiple streams from the client
	for {
		stream, err := sess.AcceptStream(context.Background())
		if err != nil {
			log.Printf("Session %s ended: %v", remoteAddr, err)
			break
		}

		// Handle each stream in a separate goroutine
		go handleStream(stream, remoteAddr.String())
	}
}

func handleStream(stream quic.Stream, clientAddr string) {
	defer stream.Close()

	streamID := stream.StreamID()
	log.Printf("Handling stream %d from %s", streamID, clientAddr)

	// Handle multiple messages on this stream
	for {
		// Set read deadline
		stream.SetReadDeadline(time.Now().Add(10 * time.Second))

		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			if err == io.EOF {
				log.Printf("Stream %d from %s closed by client", streamID, clientAddr)
			} else {
				log.Printf("Error reading from stream %d: %v", streamID, err)
			}
			break
		}

		message := string(buf[:n])
		log.Printf("Received on stream %d from %s: %s", streamID, clientAddr, message)

		// Echo message back with QUIC server info
		timestamp := time.Now().Format(time.RFC3339)
		response := fmt.Sprintf("QUIC_SERVER_ECHO[%s|stream_%d]: %s (received at %s)",
			clientAddr, streamID, message, timestamp)

		if _, err := stream.Write([]byte(response)); err != nil {
			log.Printf("Error writing to stream %d: %v", streamID, err)
			break
		}

		log.Printf("Sent response on stream %d to %s", streamID, clientAddr)
	}

	log.Printf("Stream %d with %s closed", streamID, clientAddr)
}

func logConnectionState(state quic.ConnectionState, clientAddr string) {
	log.Printf("QUIC connection established with %s", clientAddr)
	log.Printf("TLS version: TLS 1.3 (required for QUIC)")
	log.Printf("QUIC version: %s", state.Version.String())

	if state.TLS.NegotiatedProtocol != "" {
		log.Printf("ALPN negotiated: %s", state.TLS.NegotiatedProtocol)
	}

	cipherSuite := tls.CipherSuiteName(state.TLS.CipherSuite)
	log.Printf("Cipher suite: %s", cipherSuite)

	log.Printf("0-RTT attempted: %t, 0-RTT accepted: %t",
		state.Used0RTT, state.TLS.DidResume)
}
