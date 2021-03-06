package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math"
	"math/big"
	"time"
)

type CertWithKey struct {
	Name          string
	Thumbprint    string
	ShouldRenewAt time.Time
	PrivateKey    *rsa.PrivateKey
	Certificate   *x509.Certificate
}

func NewCertWithKey(name string, minTTL, maxTTL time.Duration) (*CertWithKey, error) {
	privateKey, err := generatePrivateKey()
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
		NotBefore:             time.Now().Add(-minTTL),
		NotAfter:              time.Now().Add(maxTTL),
		KeyUsage:              x509.KeyUsageCRLSign | x509.KeyUsageCertSign,
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
		Name:          name,
		Thumbprint:    calculateThumbprint(cert),
		ShouldRenewAt: cert.NotAfter.Add(-minTTL),
		PrivateKey:    privateKey,
		Certificate:   cert,
	}, nil
}
