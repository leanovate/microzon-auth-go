package memory_backend

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"sync/atomic"
	"time"
)

type memoryStore struct {
	selfCertificate   *certificates.CertWithKey
	certifcatesMap    map[string]*x509.Certificate
	revocationVersion uint64
	revocations       *revocations.Revocations
	logger            logging.Logger
}

func NewMemoryStore(parent logging.Logger) (*memoryStore, error) {
	logger := parent.WithContext(map[string]interface{}{"package": "store.memory_backend"})
	logger.Info("Start store with memory backend...")

	selfCert, err := certificates.NewCertWithKey("signer")
	if err != nil {
		return nil, err
	}
	revocations := revocations.NewRevokations(parent)
	go revocations.StartCleanup()
	return &memoryStore{
		selfCertificate:   selfCert,
		certifcatesMap:    map[string]*x509.Certificate{selfCert.Thumbprint: selfCert.Certificate},
		revocationVersion: 0,
		revocations:       revocations,
		logger:            logger,
	}, nil
}

func (s *memoryStore) SelfCertificate() *certificates.CertWithKey {
	return s.selfCertificate
}

func (s *memoryStore) AllCertificates() ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, 0, len(s.certifcatesMap))

	for _, certificate := range s.certifcatesMap {
		result = append(result, certificate)
	}
	return result, nil
}

func (s *memoryStore) CertificateByThumbprint(x5t string) (*x509.Certificate, error) {
	if certificate, ok := s.certifcatesMap[x5t]; ok {
		return certificate, nil
	}
	return nil, nil
}

func (s *memoryStore) AddRevocation(sha256 revocations.RawSha256, expiresAt time.Time) error {
	version := atomic.AddUint64(&s.revocationVersion, 1)

	s.revocations.AddRevocation(version, sha256, expiresAt)

	return nil
}

func (s *memoryStore) ListRevocations(sinceVersion uint64) (*revocations.RevokationListVO, error) {
	return s.revocations.GetRevocationsSinceVersion(sinceVersion), nil
}

func (s *memoryStore) IsRevoked(sha256 revocations.RawSha256) (bool, error) {
	return s.revocations.ContainsHash(sha256), nil
}

func (r *memoryStore) Close() {
}
