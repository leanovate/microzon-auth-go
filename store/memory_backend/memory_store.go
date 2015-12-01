package memory_backend

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type memoryStore struct {
	lock              sync.RWMutex
	selfCertificate   *certificates.CertWithKey
	certificatesMap   map[string]*x509.Certificate
	revocationVersion uint64
	revocations       *revocations.Revocations
	logger            logging.Logger
	config            *config.StoreConfig
}

func NewMemoryStore(config *config.StoreConfig, parent logging.Logger) (*memoryStore, error) {
	logger := parent.WithContext(map[string]interface{}{"package": "store.memory_backend"})
	logger.Info("Start store with memory backend...")

	revocations := revocations.NewRevocations(parent)
	go revocations.StartCleanup()
	return &memoryStore{
		selfCertificate:   nil,
		certificatesMap:   make(map[string]*x509.Certificate, 0),
		revocationVersion: 0,
		revocations:       revocations,
		logger:            logger,
		config:            config,
	}, nil
}

func (s *memoryStore) SelfCertificate() (*certificates.CertWithKey, error) {
	s.lock.RLock()
	if s.selfCertificate == nil || s.selfCertificate.ShouldRenewAt.Before(time.Now()) {
		s.lock.RUnlock()
		s.lock.Lock()
		defer s.lock.Unlock()

		if s.selfCertificate == nil || s.selfCertificate.ShouldRenewAt.Before(time.Now()) {
			s.logger.Info("Creating new certificate")
			hostname, err := os.Hostname()
			if err != nil {
				return nil, err
			}
			selfCert, err := certificates.NewCertWithKey(hostname, s.config.MinCertificateTTL, s.config.MaxCertificateTTL)
			if err != nil {
				return nil, err
			}
			s.certificatesMap[selfCert.Thumbprint] = selfCert.Certificate
			s.selfCertificate = selfCert
			return s.selfCertificate, nil
		}
		return s.selfCertificate, nil
	}
	defer s.lock.RUnlock()

	return s.selfCertificate, nil
}

func (s *memoryStore) AllCertificates() ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, 0, len(s.certificatesMap))

	for _, certificate := range s.certificatesMap {
		result = append(result, certificate)
	}
	return result, nil
}

func (s *memoryStore) CertificateByThumbprint(x5t string) (*x509.Certificate, error) {
	if certificate, ok := s.certificatesMap[x5t]; ok {
		return certificate, nil
	}
	return nil, nil
}

func (s *memoryStore) AddRevocation(sha256 revocations.RawSha256, expiresAt time.Time) error {
	version := atomic.AddUint64(&s.revocationVersion, 1)

	s.revocations.AddRevocation(version, sha256, expiresAt)

	return nil
}

func (s *memoryStore) ListRevocations(sinceVersion uint64, maxLength uint) (*revocations.RevocationListVO, error) {
	return s.revocations.GetRevocationsSinceVersion(sinceVersion, maxLength), nil
}

func (s *memoryStore) CurrentRevocationsVersion() uint64 {
	return s.revocations.CurrentVersion()
}

func (s *memoryStore) ObserveRevocationsVersion(version uint64, timeout time.Duration) chan revocations.ObserveState {
	return s.revocations.Observe.AddObserverWithTimeout(revocations.ObserveState(version), timeout)
}

func (s *memoryStore) IsRevoked(sha256 revocations.RawSha256) (bool, error) {
	return s.revocations.ContainsHash(sha256), nil
}

func (r *memoryStore) Close() {
}
