package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"os"
)

func RunClient() error {
	// Load client certificate and key
	cert, err := tls.LoadX509KeyPair("./mtls/certs/client-cert.pem", "./mtls/certs/client-key.pem")
	if err != nil {
		return fmt.Errorf("failed to load client certificate: %v", err)
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

	// Create TLS config with client certificate
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   "localhost", // Must match CN in server cert
		MinVersion:   tls.VersionTLS12,
	}

	conn, err := tls.Dial("tcp", "localhost:9443", config)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer conn.Close()

	log.Println("Connected to mTLS server")

	message := "Hello from mTLS client"
	if _, err := conn.Write([]byte(message)); err != nil {
		return fmt.Errorf("failed to send message: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		return fmt.Errorf("failed to read response: %v", err)
	}

	log.Printf("Server response: %s", string(buf[:n]))
	return nil
}
