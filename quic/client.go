package quic

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	quic "github.com/quic-go/quic-go"
)

func RunClient() error {
	// Load CA certificate
	caCert, err := os.ReadFile("./quic/certs/ca-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %v", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to add CA certificate to pool")
	}

	// TLS config for QUIC (TLS 1.3 enforced)
	tlsConf := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS13, // QUIC requires TLS 1.3
		MaxVersion: tls.VersionTLS13,
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

	log.Printf("QUIC Client Config: TLS1.3, ServerName=%s, ALPN=%v",
		tlsConf.ServerName, tlsConf.NextProtos)

	// Connect to QUIC server
	log.Println("Connecting to QUIC server...")
	sess, err := quic.DialAddr(context.Background(), "localhost:4242", tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("failed to connect to QUIC server: %v", err)
	}
	defer sess.CloseWithError(0, "client done")

	log.Println("QUIC connection established")

	// Log connection details
	logConnectionDetails(sess)

	// Test multiple streams and messages
	if err := testMultipleStreams(sess); err != nil {
		return fmt.Errorf("multi-stream test failed: %v", err)
	}

	// Test single stream with multiple messages
	if err := testSingleStreamMultipleMessages(sess); err != nil {
		return fmt.Errorf("single stream test failed: %v", err)
	}

	log.Println("QUIC client completed successfully")
	return nil
}

func logConnectionDetails(sess quic.Connection) {
	state := sess.ConnectionState()

	log.Printf("QUIC connection details:")
	log.Printf("  Remote address: %s", sess.RemoteAddr())
	log.Printf("  QUIC version: %s", state.Version.String())
	log.Printf("  TLS version: TLS 1.3 (required for QUIC)")

	if state.TLS.NegotiatedProtocol != "" {
		log.Printf("  ALPN negotiated: %s", state.TLS.NegotiatedProtocol)
	}

	cipherSuite := tls.CipherSuiteName(state.TLS.CipherSuite)
	log.Printf("  Cipher suite: %s", cipherSuite)

	log.Printf("  0-RTT used: %t, TLS resumed: %t",
		state.Used0RTT, state.TLS.DidResume)

	// Verify server certificate
	if len(state.TLS.PeerCertificates) > 0 {
		serverCert := state.TLS.PeerCertificates[0]
		log.Printf("  Server certificate: Subject=%s, Issuer=%s",
			serverCert.Subject, serverCert.Issuer)

		if err := verifyServerCertificate(serverCert); err != nil {
			log.Printf("  Server certificate verification failed: %v", err)
		} else {
			log.Printf("  Server certificate verified successfully")
		}
	}
}

func verifyServerCertificate(cert *x509.Certificate) error {
	// Load CA certificate for verification
	caCert, err := os.ReadFile("./quic/certs/ca-cert.pem")
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

func testMultipleStreams(sess quic.Connection) error {
	log.Println("Testing multiple concurrent streams...")

	// Test 3 concurrent streams
	streamCount := 3
	results := make(chan error, streamCount)

	for i := 0; i < streamCount; i++ {
		go func(streamNum int) {
			stream, err := sess.OpenStreamSync(context.Background())
			if err != nil {
				results <- fmt.Errorf("failed to open stream %d: %v", streamNum, err)
				return
			}
			defer stream.Close()

			message := fmt.Sprintf("Hello from QUIC client stream %d", streamNum)
			log.Printf("Sending on stream %d: %s", stream.StreamID(), message)

			if _, err := stream.Write([]byte(message)); err != nil {
				results <- fmt.Errorf("failed to send on stream %d: %v", streamNum, err)
				return
			}

			buf := make([]byte, 1024)
			n, err := stream.Read(buf)
			if err != nil && err != io.EOF {
				results <- fmt.Errorf("failed to read from stream %d: %v", streamNum, err)
				return
			}

			response := string(buf[:n])
			log.Printf("Received on stream %d: %s", stream.StreamID(), response)
			results <- nil
		}(i)
	}

	// Wait for all streams to complete
	for i := 0; i < streamCount; i++ {
		if err := <-results; err != nil {
			return err
		}
	}

	log.Printf("Successfully completed %d concurrent streams", streamCount)
	return nil
}

func testSingleStreamMultipleMessages(sess quic.Connection) error {
	log.Println("Testing single stream with multiple messages...")

	stream, err := sess.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open stream: %v", err)
	}
	defer stream.Close()

	messages := []string{
		"First message on single stream",
		"Second message testing persistence",
		"Third message confirming stream reuse",
		"Final message on this stream",
	}

	for i, message := range messages {
		log.Printf("Sending message %d/%d on stream %d: %s",
			i+1, len(messages), stream.StreamID(), message)

		if _, err := stream.Write([]byte(message)); err != nil {
			return fmt.Errorf("failed to send message %d: %v", i+1, err)
		}

		// Set read deadline
		stream.SetReadDeadline(time.Now().Add(5 * time.Second))

		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil && err != io.EOF {
			return fmt.Errorf("failed to read response %d: %v", i+1, err)
		}

		response := string(buf[:n])
		log.Printf("Received response %d on stream %d: %s",
			i+1, stream.StreamID(), response)

		// Small delay between messages
		time.Sleep(200 * time.Millisecond)
	}

	log.Printf("Successfully completed %d messages on single stream %d",
		len(messages), stream.StreamID())
	return nil
}
