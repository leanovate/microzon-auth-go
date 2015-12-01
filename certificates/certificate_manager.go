package certificates

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"os"
	"sync"
	"time"
)

type CertificateManager struct {
	lock            sync.RWMutex
	selfCertificate *CertWithKey
	certificates    map[string]*x509.Certificate
	store           store.Store
	logger          logging.Logger
	config          *config.StoreConfig
}

func NewCertificateManager(store store.Store, config *config.StoreConfig, parent logging.Logger) *CertificateManager {
	return &CertificateManager{
		certificates: make(map[string]*x509.Certificate, 0),
		store:        store,
		logger:       parent.WithContext(map[string]interface{}{"package": "certificates"}),
		config:       config,
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

func (s *CertificateManager) ListAllCertificates() ([]*x509.Certificate, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	result := make([]*x509.Certificate, 0, len(s.certificates))

	for _, certificate := range s.certificates {
		result = append(result, certificate)
	}
	return result, nil
}

func (s *CertificateManager) FindCertificate(thumbprint string) (*x509.Certificate, error) {
	s.lock.RLock()

	if certificate := s.certificates[thumbprint]; certificate != nil {
		s.lock.RUnlock()
		return certificate, nil
	}
	s.lock.RUnlock()

	if certificate, err := s.store.FindCertificate(thumbprint); err != nil {
		return nil, err
	} else if certificate != nil {
		s.lock.Lock()
		defer s.lock.Unlock()

		s.certificates[thumbprint] = certificate

		return certificate, nil
	}
	return nil, nil
}

func (s *CertificateManager) Close() error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.selfCertificate == nil {
		return nil
	}
	return s.store.RemoveCertificate(s.selfCertificate.Thumbprint)
}
