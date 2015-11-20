package redis_backend

import (
	"github.com/garyburd/redigo/redis"
	"github.com/leanovate/microzon-auth-go/config"
	"time"
)

func newRedisPool(config *config.StoreConfig) *redis.Pool {
	return &redis.Pool{
		MaxIdle:     3,
		IdleTimeout: 5 * time.Minute,
		Dial: func() (redis.Conn, error) {
			return redis.Dial("tcp", config.RedisAddress)
		},
		TestOnBorrow: func(conn redis.Conn, t time.Time) error {
			_, err := conn.Do("PING")
			return err
		},
	}
}
