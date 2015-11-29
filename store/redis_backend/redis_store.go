package redis_backend

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"time"
)

type redisStore struct {
	selfCertificate *certificates.CertWithKey
	connector       redisConnector
	revocations     *revocations.Revocations
	logger          logging.Logger
}

func NewRedisStore(config *config.StoreConfig, parent logging.Logger) (*redisStore, error) {
	logger := parent.WithContext(map[string]interface{}{"package": "store.redis_backend"})
	logger.Infof("Start store with redis backend: %s", config.RedisAddress)

	selfCert, err := certificates.NewCertWithKey("signer")
	if err != nil {
		return nil, err
	}
	redisStore := &redisStore{
		selfCertificate: selfCert,
		connector:       newRedisConnector(config),
		revocations:     revocations.NewRevokations(parent),
		logger:          logger,
	}

	if err := redisStore.storeSelfCertificate(); err != nil {
		redisStore.Close()
		return nil, err
	}
	go redisStore.startListenRevocationUpdates()
	go redisStore.revocations.StartCleanup()

	return redisStore, nil
}

func (r *redisStore) SelfCertificate() *certificates.CertWithKey {
	return r.selfCertificate
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

func (s *redisStore) IsRevoked(sha256 revocations.RawSha256) (bool, error) {
	return s.revocations.ContainsHash(sha256), nil
}

func (r *redisStore) Close() {
	r.logger.Info("Closing store with redis backend...")
	r.removeSelfCertificate()
	r.connector.close()
}
