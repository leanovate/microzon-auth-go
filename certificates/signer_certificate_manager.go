package certificates

import (
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"os"
	"time"
)

type SignerCertificateManager struct {
	*CertificateManager
	selfCertificate *CertWithKey
}

func NewSignerCertificateManager(store store.Store, config *config.StoreConfig, parent logging.Logger) *SignerCertificateManager {
	return &SignerCertificateManager{
		CertificateManager: NewCertificateManager(store, config, parent),
	}
}

func (s *SignerCertificateManager) GetSelfCertificate() (*CertWithKey, error) {
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
			if err := s.store.AddCertificate(selfCert.Thumbprint, selfCert.Certificate); err != nil {
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

func (s *SignerCertificateManager) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.selfCertificate == nil {
		return nil
	}
	return s.store.RemoveCertificate(s.selfCertificate.Thumbprint)
}
