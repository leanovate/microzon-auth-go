package redis_backend

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"os"
	"sync"
	"time"
)

type redisStore struct {
	lock            sync.RWMutex
	selfCertificate *certificates.CertWithKey
	connector       redisConnector
	revocations     *revocations.Revocations
	logger          logging.Logger
	config          *config.StoreConfig
}

func NewRedisStore(config *config.StoreConfig, parent logging.Logger) (*redisStore, error) {
	logger := parent.WithContext(map[string]interface{}{"package": "store.redis_backend"})
	logger.Infof("Start store with redis backend: %s", config.RedisAddress)

	redisStore := &redisStore{
		selfCertificate: nil,
		connector:       newRedisConnector(config),
		revocations:     revocations.NewRevokations(parent),
		logger:          logger,
		config:          config,
	}

	go redisStore.startListenRevocationUpdates()
	go redisStore.revocations.StartCleanup()

	return redisStore, nil
}

func (r *redisStore) SelfCertificate() (*certificates.CertWithKey, error) {
	r.lock.RLock()
	if r.selfCertificate == nil || r.selfCertificate.ShouldRenewAt.Before(time.Now()) {
		r.lock.RUnlock()
		r.lock.Lock()
		defer r.lock.Unlock()

		if r.selfCertificate == nil || r.selfCertificate.ShouldRenewAt.Before(time.Now()) {
			r.logger.Info("Creating new certificate")
			hostname, err := os.Hostname()
			if err != nil {
				return nil, err
			}
			selfCert, err := certificates.NewCertWithKey(hostname, r.config.MinCertificateTTL, r.config.MaxCertificateTTL)
			if err != nil {
				return nil, err
			}
			r.selfCertificate = selfCert
			if err := r.storeSelfCertificate(); err != nil {
				return nil, err
			}
			return r.selfCertificate, nil
		}
		return r.selfCertificate, nil
	}
	defer r.lock.RUnlock()

	return r.selfCertificate, nil
}

func (r *redisStore) AllCertificates() ([]*x509.Certificate, error) {
	return r.scanCertificates()
}

func (r *redisStore) CertificateByThumbprint(x5t string) (*x509.Certificate, error) {
	return r.getCertificateByX5t(x5t)
}

func (s *redisStore) AddRevocation(sha256 revocations.RawSha256, expiresAt time.Time) error {
	return s.insertRevocation(sha256, expiresAt)
}

func (s *redisStore) ListRevocations(sinceVersion uint64) (*revocations.RevocationListVO, error) {
	return s.revocations.GetRevocationsSinceVersion(sinceVersion), nil
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
	r.removeSelfCertificate()
	r.connector.close()
}
