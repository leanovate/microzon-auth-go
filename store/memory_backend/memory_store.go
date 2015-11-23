package memory_backend

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revokations"
	"sync/atomic"
	"time"
)

type memoryStore struct {
	selfCertificate   *certificates.CertWithKey
	certifcatesMap    map[string]*x509.Certificate
	revokationVersion uint64
	revokations       map[uint64]*revokations.RevokationVO
	logger            logging.Logger
}

func NewMemoryStore(parent logging.Logger) (*memoryStore, error) {
	logger := parent.WithContext(map[string]interface{}{"package": "store.memory_backend"})
	logger.Info("Start store with memory backend...")

	selfCert, err := certificates.NewCertWithKey("signer")
	if err != nil {
		return nil, err
	}
	return &memoryStore{
		selfCertificate:   selfCert,
		certifcatesMap:    map[string]*x509.Certificate{selfCert.Thumbprint: selfCert.Certificate},
		revokationVersion: 0,
		logger:            logger,
	}, nil
}

func (s *memoryStore) SelfCertificate() (*certificates.CertWithKey, error) {
	return s.selfCertificate, nil
}

func (s *memoryStore) AllCertificates() ([]*certificates.CertificateVO, error) {
	result := make([]*certificates.CertificateVO, 0, len(s.certifcatesMap))

	for _, certificate := range s.certifcatesMap {
		result = append(result, certificates.NewCertificateVO(certificate))
	}
	return result, nil
}

func (s *memoryStore) CertificateByThumbprint(x5t string) (*certificates.CertificateVO, error) {
	if certificate, ok := s.certifcatesMap[x5t]; ok {
		return certificates.NewCertificateVO(certificate), nil
	}
	return nil, nil
}

func (s *memoryStore) AddRevokation(sha256 string, expiresAt time.Time) error {
	version := atomic.AddUint64(&s.revokationVersion, 1)

	s.revokations[version] = revokations.NewRevokationVO(version, sha256, expiresAt)

	return nil
}

func (s *memoryStore) ListRevokations(sinceVersion uint64) (*revokations.RevokationListVO, error) {
	version := atomic.LoadUint64(&s.revokationVersion)
	result := make([]*revokations.RevokationVO, 0)

	for version, revokation := range s.revokations {
		if version > 0 {
			result = append(result, revokation)
		}
	}

	return revokations.NewRevokationListVO(version, result), nil
}

func (r *memoryStore) Close() {
}
