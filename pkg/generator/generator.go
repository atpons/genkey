package generator

import (
	"crypto/rand"
	"crypto/rsa"
)

type Generator struct {
	size int
}

func NewGenerator() *Generator {
	return &Generator{
		size: 2048,
	}
}

func (g *Generator) Generate() (*rsa.PrivateKey, error) {
	k, err := rsa.GenerateKey(rand.Reader, g.size)
	if err != nil {
		return nil, err
	}
	return k, nil
}

