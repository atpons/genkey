package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

type CertificateAuthority struct {
	PrivateKey *rsa.PrivateKey
	CA *x509.Certificate
}

func NewCertificateAuthority(privKey *rsa.PrivateKey, name *pkix.Name) *CertificateAuthority {
	return &CertificateAuthority{
		PrivateKey: privKey,
		CA: &x509.Certificate{
			SerialNumber: big.NewInt(2048),
			Subject: *name,
			NotBefore: time.Now(),
			NotAfter: time.Now().AddDate(10, 0, 0),
			IsCA: true,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
			KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
			BasicConstraintsValid: true,
		},
	}
}

func (c *CertificateAuthority) Generate() ([]byte, error) {
	cb, err := x509.CreateCertificate(rand.Reader, c.CA, c.CA, &c.PrivateKey.PublicKey, c.PrivateKey)
	if err != nil {
		return nil, err
	}
	return cb, err
}