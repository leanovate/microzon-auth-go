package store

import (
	"crypto/x509"
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
	"github.com/leanovate/microzon-auth-go/store/redis_backend"
	"strings"
	"time"
)

// Server storage backend
type ServerStore interface {
	AgentStore

	// Add a certificate to the store
	AddCertificate(thumbprint string, certificate *x509.Certificate) error

	// Remove a certificate by is thumbprint
	RemoveCertificate(thumbprint string) error

	// Add a revocation
	// The revocation has to be send to the listener with its version number
	AddRevocation(sha256 common.RawSha256, expiresAt time.Time) error
}

func NewStore(config *config.StoreConfig, logger logging.Logger) (ServerStore, error) {
	switch strings.ToLower(config.StoreType) {
	case "memory":
		return memory_backend.NewMemoryStore(config, logger)
	case "redis":
		return redis_backend.NewRedisStore(config, logger)
	default:
		return nil, errors.Errorf("Unknown store type: %s", config.StoreType)
	}
}
