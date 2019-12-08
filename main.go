package main

import (
	"crypto/x509/pkix"
	"log"

	"github.com/atpons/genkey/pkg/ca"
	"github.com/atpons/genkey/pkg/generator"
	"github.com/atpons/genkey/pkg/pem"
)

func main() {
	if err := routine(); err != nil {
		log.Fatal(err)
	}
}

func routine() error {
	g := generator.NewGenerator()
	priv, err := g.Generate()
	if err != nil {
		return err
	}

	if err := pem.EncodePrivateKey(priv, "server.key"); err != nil {
		return err
	}

	c := ca.NewCertificateAuthority(priv, &pkix.Name{
		Country:      []string{"JP"},
		Organization: []string{"IGGG"},
		Locality:     []string{"Gunma"},
		CommonName:   "dev.iggg.org",
	})

	if err := pem.EncodeCertificate(c, "server.crt"); err != nil {
		return err
	}
	return nil
}
