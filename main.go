package main

import (
	"bufio"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	"io"
	"log"
	"os"
)

var file io.Reader

func init() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		log.Fatalf("usage: %s </path/to/public.key>", os.Args[0])
	}

	if os.Args[1] == "-h" || os.Args[1] == "--help" {
		log.Println("fingerprint - prints the fingerprint of the PGP public key inside the supplied file")
		log.Fatalf("usage: %s </path/to/public.key>", os.Args[0])
	}

	if os.Args[1] == "-" {
		file = bufio.NewReader(os.Stdin)
	} else {
		if fileDisk, err := os.Open(os.Args[1]); err != nil {
			log.Fatalf("Error reading the supplied file (%s)", err)
		} else {
			file = fileDisk
		}
	}
}

func main() {
	decoded, err := armor.Decode(file)

	if err != nil {
		log.Fatalf("Error decoding the supplied file (%s)", err)
	}

	if decoded.Type != openpgp.PublicKeyType {
		log.Fatal("Error finding a public key within the supplied file")
	}

	body := packet.NewReader(decoded.Body)
	entity, err := openpgp.ReadEntity(body)

	if err != nil {
		log.Fatal("Error reading a public key within the supplied data (%s)", err)
	}

	log.Printf("%x\n", entity.PrimaryKey.Fingerprint)
}
