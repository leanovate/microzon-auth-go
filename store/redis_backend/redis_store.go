package redis_backend

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"sync"
	"time"
)

type redisStore struct {
	lock        sync.RWMutex
	connector   redisConnector
	revocations *revocations.Revocations
	logger      logging.Logger
	config      *config.StoreConfig
}

func NewRedisStore(config *config.StoreConfig, parent logging.Logger) (*redisStore, error) {
	logger := parent.WithContext(map[string]interface{}{"package": "store.redis_backend"})
	logger.Infof("Start store with redis backend: %s", config.RedisAddress)

	redisStore := &redisStore{
		connector:   newRedisConnector(config),
		revocations: revocations.NewRevocations(parent),
		logger:      logger,
		config:      config,
	}

	go redisStore.startListenRevocationUpdates()
	go redisStore.revocations.StartCleanup()

	if err := redisStore.scanRevocations(); err != nil {
		return nil, err
	}

	return redisStore, nil
}

func (r *redisStore) AllCertificates() ([]*x509.Certificate, error) {
	return r.scanCertificates()
}

func (r *redisStore) FindCertificate(thumbprint string) (*x509.Certificate, error) {
	return r.getCertificateByX5t(thumbprint)
}

func (s *redisStore) AddRevocation(sha256 revocations.RawSha256, expiresAt time.Time) error {
	return s.insertRevocation(sha256, expiresAt)
}

func (s *redisStore) ListRevocations(sinceVersion uint64, maxLength int) (*revocations.RevocationListVO, error) {
	return s.revocations.GetRevocationsSinceVersion(sinceVersion, maxLength), nil
}

func (s *redisStore) CurrentRevocationsVersion() uint64 {
	return s.revocations.CurrentVersion()
}

func (s *redisStore) ObserveRevocationsVersion(version uint64, timeout time.Duration) chan revocations.ObserveState {
	return s.revocations.Observe.AddObserverWithTimeout(revocations.ObserveState(version), timeout)
}

func (s *redisStore) IsRevoked(sha256 revocations.RawSha256) (bool, error) {
	return s.revocations.ContainsHash(sha256), nil
}

func (r *redisStore) Close() {
	r.logger.Info("Closing store with redis backend...")
	r.connector.close()
}
