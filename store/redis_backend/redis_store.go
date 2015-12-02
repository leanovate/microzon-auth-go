package redis_backend

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"sync"
	"time"
)

type redisStore struct {
	lock                sync.RWMutex
	connector           redisConnector
	logger              logging.Logger
	config              *config.StoreConfig
	revocationsListener *redisRevocationsListener
}

func NewRedisStore(config *config.StoreConfig, parent logging.Logger) (*redisStore, error) {
	logger := parent.WithContext(map[string]interface{}{"package": "store.redis_backend"})
	logger.Infof("Start store with redis backend: %s", config.RedisAddress)

	redisStore := &redisStore{
		connector: newRedisConnector(config),
		logger:    logger,
		config:    config,
	}

	return redisStore, nil
}

func (r *redisStore) AllCertificates() ([]*x509.Certificate, error) {
	return r.scanCertificates()
}

func (r *redisStore) FindCertificate(thumbprint string) (*x509.Certificate, error) {
	return r.getCertificateByX5t(thumbprint)
}

func (r *redisStore) AddRevocation(sha256 common.RawSha256, expiresAt time.Time) error {
	return r.insertRevocation(sha256, expiresAt)
}

func (r *redisStore) SetRevocationsListener(listener common.RevocationsListener) error {
	revocationsListener, err := newRedisRevocationsListener(r.connector, listener, r.logger)
	if err != nil {
		return err
	}
	r.revocationsListener = revocationsListener
	return nil
}

func (r *redisStore) Close() {
	r.logger.Info("Closing store with redis backend...")
	r.connector.close()
}
