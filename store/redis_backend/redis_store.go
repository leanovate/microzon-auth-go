package redis_backend

import (
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revokations"
	"gopkg.in/redis.v3"
	"time"
)

type redisStore struct {
	selfCertificate *certificates.CertWithKey
	redisClient     *redis.Client
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
		redisClient:     newRedisClient(config),
		logger:          logger,
	}

	if err := redisStore.storeSelfCertificate(); err != nil {
		redisStore.Close()
		return nil, err
	}

	return redisStore, nil
}

func (r *redisStore) SelfCerificate() (*certificates.CertWithKey, error) {
	return r.selfCertificate, nil
}

func (r *redisStore) AllCertificates() ([]*certificates.CertificateVO, error) {
	certs, err := r.scanCertificates()
	if err != nil {
		return nil, err
	}
	result := make([]*certificates.CertificateVO, 0, len(certs))
	for _, cert := range certs {
		result = append(result, certificates.NewCertificateVO(cert))
	}
	return result, nil
}

func (r *redisStore) CertificateByThumbprint(x5t string) (*certificates.CertificateVO, error) {
	cert, err := r.getCertificateBySki(x5t)
	if err != nil {
		return nil, err
	}
	if cert != nil {
		return certificates.NewCertificateVO(cert), nil
	}
	return nil, nil
}

func (s *redisStore) AddRevokation(sha256 string, expiresAt time.Time) error {
	return nil
}

func (s *redisStore) ListRevokations(sinceVersion uint64) (*revokations.RevokationListVO, error) {
	return nil, nil
}

func (r *redisStore) Close() {
	r.logger.Info("Closing store with redis backend...")
	r.removeSelfCertificate()
	r.redisClient.Close()
}
