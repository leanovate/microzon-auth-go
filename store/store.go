package store

import (
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
	"github.com/leanovate/microzon-auth-go/store/redis_backend"
	"strings"
)

type Store interface {
	SelfCerificate() (*certificates.CertWithKey, error)
	AllCertificates() ([]*certificates.CertificateVO, error)
	CertificateBySKI(ski string) (*certificates.CertificateVO, error)
	Close()
}

func NewStore(config *config.StoreConfig, logger logging.Logger) (Store, error) {
	switch strings.ToLower(config.StoreType) {
	case "memory":
		return memory_backend.NewMemoryStore(logger)
	case "redis":
		return redis_backend.NewRedisStore(config, logger)
	default:
		return nil, errors.Errorf("Unknown store type: %s", config.StoreType)
	}
}
