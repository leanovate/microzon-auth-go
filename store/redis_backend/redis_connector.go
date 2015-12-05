package redis_backend

import (
	"github.com/leanovate/microzon-auth-go/config"
	"gopkg.in/redis.v3"
)

type redisConnector interface {
	getClient(key string) (*redis.Client, error)
	close() error
}

type singleRedisConnector struct {
	client *redis.Client
}

func newRedisConnector(config *config.StoreConfig) redisConnector {
	opts := &redis.Options{
		Addr:     config.RedisAddress,
		PoolSize: 20,
		DB:       0,
	}
	return &singleRedisConnector{
		client: redis.NewClient(opts),
	}
}

func (r *singleRedisConnector) getClient(key string) (*redis.Client, error) {
	return r.client, nil
}

func (r *singleRedisConnector) close() error {
	return r.client.Close()
}
