package memory_backend

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"sync/atomic"
	"time"
)

type memoryStore struct {
	certificatesMap   map[string]*x509.Certificate
	revocationVersion uint64
	logger            logging.Logger
	config            *config.StoreConfig
	listener          common.RevocationsListener
}

func NewMemoryStore(config *config.StoreConfig, parent logging.Logger) (*memoryStore, error) {
	logger := parent.WithContext(map[string]interface{}{"package": "store.memory_backend"})
	logger.Info("Start store with memory backend...")

	return &memoryStore{
		certificatesMap:   make(map[string]*x509.Certificate, 0),
		revocationVersion: 0,
		logger:            logger,
		config:            config,
	}, nil
}

func (r *memoryStore) AddCertificate(thumbprint string, certificate *x509.Certificate) error {
	r.certificatesMap[thumbprint] = certificate
	return nil
}

func (r *memoryStore) RemoveCertificate(thumbprint string) error {
	delete(r.certificatesMap, thumbprint)
	return nil
}

func (s *memoryStore) AllCertificates() ([]*x509.Certificate, error) {
	result := make([]*x509.Certificate, 0, len(s.certificatesMap))

	for _, certificate := range s.certificatesMap {
		result = append(result, certificate)
	}
	return result, nil
}

func (s *memoryStore) FindCertificate(thumbprint string) (*x509.Certificate, error) {
	if certificate, ok := s.certificatesMap[thumbprint]; ok {
		return certificate, nil
	}
	return nil, nil
}

func (s *memoryStore) AddRevocation(sha256 common.RawSha256, expiresAt time.Time) error {
	version := atomic.AddUint64(&s.revocationVersion, 1)

	if s.listener != nil {
		s.listener(version, sha256, expiresAt)
	}

	return nil
}

func (s *memoryStore) SetRevocationsListener(listener common.RevocationsListener) error {
	s.listener = listener
	return nil
}

func (r *memoryStore) Close() {
}
