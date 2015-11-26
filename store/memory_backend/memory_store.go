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
	return &memoryStore{
		selfCertificate:   selfCert,
		certifcatesMap:    map[string]*x509.Certificate{selfCert.Thumbprint: selfCert.Certificate},
		revocationVersion: 0,
		revocations:       revocations.NewRevokations(parent),
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

func (s *memoryStore) AddRevocation(sha256 string, expiresAt time.Time) error {
	version := atomic.AddUint64(&s.revocationVersion, 1)

	rawSha256, err := revocations.NewRawSha256(sha256)
	if err != nil {
		return err
	}
	s.revocations.AddRevokation(revocations.NewRevocation(version, rawSha256, expiresAt))

	return nil
}

func (s *memoryStore) ListRevocations(sinceVersion uint64) (*revocations.RevokationListVO, error) {
	return s.revocations.GetRevocationsSinceVersion(sinceVersion), nil
}

func (s *memoryStore) IsRevoked(sha256 string) (bool, error) {
	rawSha256, err := revocations.NewRawSha256(sha256)
	if err != nil {
		return false, err
	}
	return s.revocations.ContainsHash(rawSha256), nil
}

func (r *memoryStore) Close() {
}
