package certificates

import (
	"crypto/x509"
	"encoding/pem"
)

type CertificateVO struct {
	X5t         string `json:"x5t"`
	ExpiresAt   int64  `json:"expires_at"`
	Certificate string `json:"certificate"`
	PublicKey   string `json:"public_key"`
}

func NewCertificateVO(certificate *x509.Certificate) *CertificateVO {
	pkixPub, _ := x509.MarshalPKIXPublicKey(certificate.PublicKey)

	return &CertificateVO{
		X5t:         calculateThumbprint(certificate),
		ExpiresAt:   certificate.NotAfter.Unix(),
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})),
		PublicKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixPub})),
	}
}
