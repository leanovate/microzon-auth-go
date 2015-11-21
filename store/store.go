package store

import (
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revokations"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
	"github.com/leanovate/microzon-auth-go/store/redis_backend"
	"strings"
)

// Storage backend
type Store interface {
	// Get own certificate with private key
	SelfCerificate() (*certificates.CertWithKey, error)

	// Get all certificates
	AllCertificates() ([]*certificates.CertificateVO, error)

	// Get a certificate by its SKI
	CertificateBySKI(ski string) (*certificates.CertificateVO, error)

	// Add a revokation
	AddRevokation(sha256 string, expiresAt int64) error

	// List all revokations since version
	ListRevokations(sinceVersion uint64) (*revokations.RevokationListVO, error)

	// Close the store
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
