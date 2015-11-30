package config

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"net/url"
	"os"
	"time"
)

type StoreConfig struct {
	StoreType         string        `json:"store_type" yaml:"store_type"`
	RedisAddress      string        `json:"redis_address" yaml:"redis_address"`
	MaxCertificateTTL time.Duration `json:"max_certificate_ttl" yaml:"max_certificate_ttl"`
	MinCertificateTTL time.Duration `json:"min_certificate_ttl" yaml:"min_certificate_ttl"`
}

func NewStoreConfig(logger logging.Logger) *StoreConfig {
	if redisPort, ok := os.LookupEnv("REDIS_PORT"); ok {
		redisPortUrl, err := url.Parse(redisPort)
		if err != nil {
			logger.Warnf("Invalid REDIS_PORT environment variable: %s", redisPort)
		} else {
			return &StoreConfig{
				StoreType:         "redis",
				RedisAddress:      redisPortUrl.Host,
				MaxCertificateTTL: 1 * time.Hour,
				MinCertificateTTL: 10 * time.Minute,
			}
		}
	}
	return &StoreConfig{
		StoreType:         "memory",
		MaxCertificateTTL: 1 * time.Hour,
		MinCertificateTTL: 10 * time.Minute,
	}
}

func readStoreConfig(fileName string) (*StoreConfig, error) {
	var storeConfig StoreConfig

	if err := loadConfigFile(fileName, &storeConfig); err != nil {
		return nil, err
	}

	return &storeConfig, nil
}
