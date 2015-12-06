package certificates

import (
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"os"
	"time"
)

type CertificateManager struct {
	*CertificateValidator
	serverStore     store.ServerStore
	selfCertificate *CertWithKey
}

func NewCertificateManager(serverStore store.ServerStore, config *config.StoreConfig, parent logging.Logger) *CertificateManager {
	return &CertificateManager{
		CertificateValidator: NewCertificateValidator(serverStore, config, parent),
		serverStore:          serverStore,
	}
}

func (s *CertificateManager) GetSelfCertificate() (*CertWithKey, error) {
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
			selfCert, err := NewCertWithKey(hostname, s.config.MinCertificateTTL, s.config.MaxCertificateTTL)
			if err != nil {
				return nil, err
			}
			s.certificates[selfCert.Thumbprint] = selfCert.Certificate
			if err := s.serverStore.AddCertificate(selfCert.Thumbprint, selfCert.Certificate); err != nil {
				return nil, err
			}
			s.selfCertificate = selfCert
			return s.selfCertificate, nil
		}
		return s.selfCertificate, nil
	}
	defer s.lock.RUnlock()

	return s.selfCertificate, nil
}

func (s *CertificateManager) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.selfCertificate == nil {
		return nil
	}
	return s.serverStore.RemoveCertificate(s.selfCertificate.Thumbprint)
}
