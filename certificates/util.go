package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
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

func calculateThumbprint(certificate *x509.Certificate) string {
	sha := sha256.New()
	sha.Write(certificate.Raw)
	return base64.URLEncoding.EncodeToString(sha.Sum(nil))
}
