package main

import (
	"flag"
	"fmt"
	"log"
	"os"
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
	default:
		fmt.Fprintf(os.Stderr, "Usage: %s -mode=[tls-server|tls-client]\n", os.Args[0])
		os.Exit(1)
	}
}
