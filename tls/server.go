package tls

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
)

func RunServer() error {
	// Load TLS certificate and private key
	cert, err := tls.LoadX509KeyPair("./tls/certs/server-cert.pem", "./tls/certs/server-key.pem")
	if err != nil {
		return fmt.Errorf("failed to load certificate: %v", err)
	}

	// Create TLS config
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// Create listener
	listener, err := tls.Listen("tcp", ":8443", config)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Println("Server listening on :8443")

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

	log.Printf("New connection from %s", conn.RemoteAddr())

	// Create buffer for reading
	buf := make([]byte, 1024)

	// Read from connection
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("Error reading from connection: %v", err)
		return
	}

	message := string(buf[:n])
	log.Printf("Received: %s", message)

	// Echo message back to client
	response := fmt.Sprintf("Server received: %s", message)
	if _, err := conn.Write([]byte(response)); err != nil {
		log.Printf("Error writing to connection: %v", err)
		return
	}
}
