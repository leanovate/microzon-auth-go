package redis_backend

import (
	"github.com/leanovate/microzon-auth-go/config"
	"gopkg.in/redis.v3"
)

func newRedisClient(config *config.StoreConfig) *redis.Client {
	opts := &redis.Options{
		Addr: config.RedisAddress,
		DB:   0,
	}
	return redis.NewClient(opts)
}
