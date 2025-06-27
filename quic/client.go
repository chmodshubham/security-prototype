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
		MinVersion: tls.VersionTLS13,
	}

	// QUIC configuration
	quicConf := &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    1000,
		MaxIncomingUniStreams: 100,
	}

	sess, err := quic.DialAddr(context.Background(), "localhost:4242", tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("failed to connect to QUIC server: %v", err)
	}
	defer sess.CloseWithError(0, "done")

	stream, err := sess.OpenStreamSync(context.Background())
	if err != nil {
		return fmt.Errorf("failed to open stream: %v", err)
	}
	defer stream.Close()

	message := "Hello from QUIC client"
	if _, err := stream.Write([]byte(message)); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read response: %v", err)
	}
	log.Printf("Server response: %s", string(buf[:n]))
	return nil
}
