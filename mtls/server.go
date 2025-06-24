package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func RunServer() error {
	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair("./mtls/certs/server-cert.pem", "./mtls/certs/server-key.pem")
	if err != nil {
		return fmt.Errorf("failed to load server certificate: %v", err)
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
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	listener, err := tls.Listen("tcp", ":9443", config)
	if err != nil {
		return fmt.Errorf("failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Println("mTLS server listening on :9443")

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
	log.Printf("New connection from %s", conn.RemoteAddr())
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		log.Printf("Error reading from connection: %v", err)
		return
	}
	message := string(buf[:n])
	log.Printf("Received: %s", message)
	response := fmt.Sprintf("mTLS server received: %s", message)
	if _, err := conn.Write([]byte(response)); err != nil {
		log.Printf("Error writing to connection: %v", err)
		return
	}
}
