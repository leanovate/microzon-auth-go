package config

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"net/url"
	"os"
)

type StoreConfig struct {
	StoreType      string `json:"store_type" yaml:"store_type"`
	RedisAddress   string `json:"redis_address" yaml:"redis_address"`
	CertificateTTL uint32 `json:"certificate_ttl" yaml:"certificate_ttl"`
}

func newStoreConfig(logger logging.Logger) *StoreConfig {
	if redisPort, ok := os.LookupEnv("REDIS_PORT"); ok {
		redisPortUrl, err := url.Parse(redisPort)
		if err != nil {
			logger.Warnf("Invalid REDIS_PORT environment variable: %s", redisPort)
		} else {
			return &StoreConfig{
				StoreType:      "redis",
				RedisAddress:   redisPortUrl.Host,
				CertificateTTL: 3600,
			}
		}
	}
	return &StoreConfig{
		StoreType: "memory",
	}
}

func readStoreConfig(fileName string) (*StoreConfig, error) {
	var storeConfig StoreConfig

	if err := loadConfigFile(fileName, &storeConfig); err != nil {
		return nil, err
	}

	return &storeConfig, nil
}
