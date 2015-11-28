package store

import (
	"crypto/x509"
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
	"github.com/leanovate/microzon-auth-go/store/redis_backend"
	"strings"
	"time"
)

// Storage backend
type Store interface {
	// Get own certificate with private key
	SelfCertificate() *certificates.CertWithKey

	// Get all certificates
	AllCertificates() ([]*x509.Certificate, error)

	// Get a certificate by its SKI
	CertificateByThumbprint(x5t string) (*x509.Certificate, error)

	// Add a revocation
	AddRevocation(sha256 revocations.RawSha256, expiresAt time.Time) error

	// List all revocations since version
	ListRevocations(sinceVersion uint64) (*revocations.RevokationListVO, error)

	// Check if a token is revoked
	IsRevoked(sha256 revocations.RawSha256) (bool, error)

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
