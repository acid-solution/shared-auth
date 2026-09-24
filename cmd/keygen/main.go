package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	out := flag.String("out", ".local/private.pem", "path to the generated PKCS#8 RSA private key")
	bits := flag.Int("bits", 2048, "RSA key size")
	flag.Parse()
	if *bits < 2048 {
		fatal(fmt.Errorf("RSA key size must be at least 2048 bits"))
	}
	if _, err := os.Stat(*out); err == nil {
		fmt.Printf("key already exists: %s\n", *out)
		return
	} else if !os.IsNotExist(err) {
		fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, *bits)
	if err != nil {
		fatal(err)
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0700); err != nil {
		fatal(err)
	}
	if err := os.WriteFile(*out, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: encoded}), 0600); err != nil {
		fatal(err)
	}
	fmt.Printf("generated RSA private key: %s\n", *out)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
