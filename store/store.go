package store

import (
	"crypto/x509"

	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/logging"
)

type Store struct {
	SelfCertificate *certificates.CertWithKey
	Certificates    map[string]*x509.Certificate
	logger          logging.Logger
}

func NewStore(logger logging.Logger) (*Store, error) {
	selfCert, err := certificates.NewCertWithKey("signer")
	if err != nil {
		return nil, err
	}
	return &Store{
		SelfCertificate: selfCert,
		Certificates:    map[string]*x509.Certificate{selfCert.Ski: selfCert.Certificate},
		logger:          logger.WithContext(map[string]interface{}{"package": "store"}),
	}, nil
}
