package tls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
)

func RunClient() error {
	// Load server's certificate
	caCert, err := os.ReadFile("./tls/certs/ca-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read certificate: %v", err)
	}

	// Create certificate pool and add server's certificate
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to add certificate to pool")
	}

	// Create TLS config
	config := &tls.Config{
		RootCAs:    caPool,
		ServerName: "localhost", // Must match CN in server cert
		MinVersion: tls.VersionTLS12,
	}

	// Connect to server
	conn, err := tls.Dial("tcp", "localhost:8443", config)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	log.Println("Connected to server")

	// Send message to server
	message := "Hello from client"
	if _, err := conn.Write([]byte(message)); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	// Read server's response
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read response: %v", err)
	}

	log.Printf("Server response: %s", string(buf[:n]))
	return nil
}
