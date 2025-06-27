package quic

import (
	"context"
	"crypto/tls"
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

	// TLS config for QUIC (TLS 1.3 enforced)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	// QUIC configuration
	quicConf := &quic.Config{
		MaxIdleTimeout:        30 * time.Second,
		KeepAlivePeriod:       10 * time.Second,
		MaxIncomingStreams:    1000,
		MaxIncomingUniStreams: 100,
	}

	listener, err := quic.ListenAddr("localhost:4242", tlsConf, quicConf)
	if err != nil {
		return fmt.Errorf("failed to start QUIC listener: %v", err)
	}

	defer listener.Close()

	log.Println("QUIC server listening on :4242")

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

	stream, err := sess.AcceptStream(context.Background())
	if err != nil {
		log.Printf("Failed to accept stream: %v", err)
		return
	}
	defer stream.Close()

	buf := make([]byte, 1024)
	n, err := stream.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("Error reading from stream: %v", err)
		return
	}
	message := string(buf[:n])
	log.Printf("Received: %s", message)

	response := fmt.Sprintf("QUIC server received: %s", message)
	if _, err := stream.Write([]byte(response)); err != nil {
		log.Printf("Error writing to stream: %v", err)
	}
}
