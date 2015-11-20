package redis_backend

import (
	"github.com/leanovate/microzon-auth-go/logging"
)

type redisStore struct {
	logger logging.Logger
}

func NewRedisStore(logger logging.Logger) (*redisStore, error) {
	return &redisStore{
		logger: logger.WithContext(map[string]interface{}{"package": "store.redis"}),
	}
}
