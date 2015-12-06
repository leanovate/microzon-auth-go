package certificates

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"sync"
)

type CertificateValidator struct {
	lock         sync.RWMutex
	certificates map[string]*x509.Certificate
	agentStore   store.AgentStore
	logger       logging.Logger
	config       *config.StoreConfig
}

func NewCertificateValidator(agentStore store.AgentStore, config *config.StoreConfig, parent logging.Logger) *CertificateValidator {
	return &CertificateValidator{
		certificates: make(map[string]*x509.Certificate, 0),
		agentStore:   agentStore,
		logger:       parent.WithContext(map[string]interface{}{"package": "certificates"}),
		config:       config,
	}
}

func (s *CertificateValidator) ListAllCertificates() ([]*x509.Certificate, error) {
	s.lock.RLock()
	defer s.lock.RUnlock()

	result := make([]*x509.Certificate, 0, len(s.certificates))

	for _, certificate := range s.certificates {
		result = append(result, certificate)
	}
	return result, nil
}

func (s *CertificateValidator) FindCertificate(thumbprint string) (*x509.Certificate, error) {
	s.lock.RLock()

	if certificate := s.certificates[thumbprint]; certificate != nil {
		s.lock.RUnlock()
		return certificate, nil
	}
	s.lock.RUnlock()

	if certificate, err := s.agentStore.FindCertificate(thumbprint); err != nil {
		return nil, err
	} else if certificate != nil {
		s.lock.Lock()
		defer s.lock.Unlock()

		s.certificates[thumbprint] = certificate

		return certificate, nil
	}
	return nil, nil
}
