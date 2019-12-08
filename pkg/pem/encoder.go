package pem

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"os"

	"github.com/atpons/genkey/pkg/ca"
)

func EncodePrivateKey(priv *rsa.PrivateKey, out string) error {
	o, err := os.Create(out)
	if err != nil {
		return err
	}
	defer o.Close()

	privKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	}

	if err = pem.Encode(o, privKey); err != nil {
		return err
	}

	return nil
}

func EncodePublicKey(pub *rsa.PublicKey, out string) error {
	oPubKey, err := os.Create(out)
	if err != nil {
		return err
	}
	defer oPubKey.Close()

	ab, err := asn1.Marshal(*pub)
	if err != nil {
		return err
	}

	pubKey := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: ab,
	}

	if err := pem.Encode(oPubKey, pubKey); err != nil {
		return err
	}
	return nil
}

func EncodeCertificate(ca *ca.CertificateAuthority, out string) error {
	cout, err := os.Create(out)
	if err != nil {
		return err
	}
	defer cout.Close()

	b, err := ca.Generate()
	if err != nil {
		return err
	}

	if err := pem.Encode(cout, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: b,
	}); err != nil {
		return err
	}
	return nil
}
