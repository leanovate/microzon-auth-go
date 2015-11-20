package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math"
	"math/big"
	"time"
)

type CertWithKey struct {
	Name        string
	Ski         string
	PrivateKey  *rsa.PrivateKey
	Certificate *x509.Certificate
}

func NewCertWithKey(name string) (*CertWithKey, error) {
	privateKey, err := generatePrivateKey()
	if err != nil {
		return nil, err
	}

	keyID, err := calculateKeyIdentifier(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   name,
			Country:      []string{"de"},
			Organization: []string{"leanovate"},
		},
		PublicKey:             privateKey.PublicKey,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
		SubjectKeyId:          keyID,
		BasicConstraintsValid: true,
	}
	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certRaw)
	if err != nil {
		return nil, err
	}

	return &CertWithKey{
		Name:        name,
		Ski:         base64.URLEncoding.EncodeToString(keyID),
		PrivateKey:  privateKey,
		Certificate: cert,
	}, nil
}