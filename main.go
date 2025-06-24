package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"security-prototype/mtls"
	"security-prototype/tls"
)

func main() {
	mode := flag.String("mode", "", "Prototype to run simulated security prototype")
	flag.Parse()

	switch *mode {
	case "tls-server":
		log.Println("Starting TLS server...")
		if err := tls.RunServer(); err != nil {
			log.Fatalf("TLS Server error: %v", err)
		}
	case "tls-client":
		log.Println("Starting TLS client...")
		if err := tls.RunClient(); err != nil {
			log.Fatalf("TLS Client error: %v", err)
		}
	case "mtls-server":
		log.Println("Starting mTLS server...")
		if err := mtls.RunServer(); err != nil {
			log.Fatalf("mTLS Server error: %v", err)
		}
	case "mtls-client":
		log.Println("Starting mTLS client...")
		if err := mtls.RunClient(); err != nil {
			log.Fatalf("mTLS Client error: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "Usage: %s -mode=[tls-server|tls-client|mtls-server|mtls-client]\n", os.Args[0])
		os.Exit(1)
	}
}
