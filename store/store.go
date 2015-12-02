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

// Storage backend
type Store interface {
	// Add a certificate to the store
	AddCertificate(thumbprint string, certificate *x509.Certificate) error

	// Find/lookup a certificate by its thumbprint
	FindCertificate(thumbprint string) (*x509.Certificate, error)

	// Get all certificates
	AllCertificates() ([]*x509.Certificate, error)

	// Remove a certificate by is thumbprint
	RemoveCertificate(thumbprint string) error

	// Add a revocation
	// The revocation has to be send to the listener with its version number
	AddRevocation(sha256 common.RawSha256, expiresAt time.Time) error

	// Set a listener for revocations
	// The implementation is supposed to send all existing revocations at once
	SetRevocationsListener(listener common.RevocationsListener) error

	// Close the store
	Close()
}

func NewStore(config *config.StoreConfig, logger logging.Logger) (Store, error) {
	switch strings.ToLower(config.StoreType) {
	case "memory":
		return memory_backend.NewMemoryStore(config, logger)
	case "redis":
		return redis_backend.NewRedisStore(config, logger)
	default:
		return nil, errors.Errorf("Unknown store type: %s", config.StoreType)
	}
}
