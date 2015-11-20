package config

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"net/url"
	"os"
)

type StoreConfig struct {
	StoreType    string `json:"storeType" yaml:"storeType"`
	RedisAddress string `json:"redisAddress" yaml:"redisAddress"`
}

func NewStoreConfig(logger logging.Logger) *StoreConfig {
	if redisPort, ok := os.LookupEnv("REDIS_PORT"); ok {
		redisPortUrl, err := url.Parse(redisPort)
		if err != nil {
			logger.Warnf("Invalid REDIS_PORT environment variable: %s", redisPort)
		} else {
			return &StoreConfig{
				StoreType:    "redis",
				RedisAddress: redisPortUrl.Host,
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
