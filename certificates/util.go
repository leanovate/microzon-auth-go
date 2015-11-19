package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/asn1"
	"math/big"
)

const (
	rsaKeyStrength = 2048
)

type rsaPublicKey struct {
	N *big.Int
	E int
}

func generatePrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, rsaKeyStrength)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func calculateKeyIdentifier(pub interface{}) ([]byte, error) {
	switch pub := pub.(type) {
	case *rsa.PublicKey:
		bytes, err := asn1.Marshal(rsaPublicKey{
			N: pub.N,
			E: pub.E,
		})
		if err != nil {
			return nil, err
		}
		sha := sha1.New()
		sha.Write(bytes)
		return sha.Sum(nil), nil
	default:
		return nil, nil
	}
}
