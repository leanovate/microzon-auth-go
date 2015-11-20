package memory_backend

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/logging"
)

type memoryStore struct {
	selfCertificate *certificates.CertWithKey
	certifcatesMap  map[string]*x509.Certificate
	logger          logging.Logger
}

func NewMemoryStore(logger logging.Logger) (*memoryStore, error) {
	selfCert, err := certificates.NewCertWithKey("signer")
	if err != nil {
		return nil, err
	}
	return &memoryStore{
		selfCertificate: selfCert,
		certifcatesMap:  map[string]*x509.Certificate{selfCert.Ski: selfCert.Certificate},
		logger:          logger.WithContext(map[string]interface{}{"package": "store.memory"}),
	}, nil
}

func (s *memoryStore) SelfCerificate() (*certificates.CertWithKey, error) {
	return s.selfCertificate, nil
}

func (s *memoryStore) AllCertificates() ([]*certificates.CertificateVO, error) {
	result := make([]*certificates.CertificateVO, 0, len(s.certifcatesMap))

	for _, certificate := range s.certifcatesMap {
		result = append(result, certificates.NewCertificateVO(certificate))
	}
	return result, nil
}

func (s *memoryStore) CertificateBySKI(ski string) (*certificates.CertificateVO, error) {
	if certificate, ok := s.certifcatesMap[ski]; ok {
		return certificates.NewCertificateVO(certificate), nil
	}
	return nil, nil
}
