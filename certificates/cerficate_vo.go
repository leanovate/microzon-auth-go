package certificates

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
)

type CertificateVO struct {
	Ski         string `json:"ski"`
	ExpiresAt   int64  `json:"expires_at"`
	Certificate string `json:"certificate"`
	PublicKey   string `json:"public_key"`
}

func NewCertificateVO(certificate *x509.Certificate) *CertificateVO {
	pkixPub, _ := x509.MarshalPKIXPublicKey(certificate.PublicKey)

	return &CertificateVO{
		Ski:         base64.URLEncoding.EncodeToString(certificate.SubjectKeyId),
		ExpiresAt:   certificate.NotAfter.Unix(),
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})),
		PublicKey:   string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkixPub})),
	}
}
