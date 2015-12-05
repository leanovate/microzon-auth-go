package redis_backend

import (
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/logging"
	"gopkg.in/redis.v3"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const keyRevocationsPublish = "revocations"
const keyRevocationVersionCounter = "revocations:version"

type redisRevocationsListener struct {
	lastVersion uint64
	connector   redisConnector
	listener    common.RevocationsListener
	logger      logging.Logger
}

func newRedisRevocationsListener(connector redisConnector, listener common.RevocationsListener, logger logging.Logger) (*redisRevocationsListener, error) {
	redisListener := &redisRevocationsListener{
		lastVersion: 0,
		connector:   connector,
		listener:    listener,
		logger:      logger,
	}

	if err := redisListener.fetchLastVersion(); err != nil {
		return nil, err
	}

	go redisListener.startListenRevocationUpdates()

	if err := redisListener.scanRevocations(); err != nil {
		return nil, err
	}

	return redisListener, nil
}

func (r *redisRevocationsListener) fetchLastVersion() error {
	client, err := r.connector.getClient("")
	if err != nil {
		return errors.Wrap(err, 0)
	}
	value, err := client.Get(keyRevocationVersionCounter).Result()
	if err == redis.Nil {
		return nil
	} else if err != nil {
		return errors.Wrap(err, 0)
	}
	version, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	r.lastVersion = version
	return nil
}

func (r *redisRevocationsListener) scanRevocations() error {
	client, err := r.connector.getClient("")
	if err != nil {
		return errors.Wrap(err, 0)
	}
	var cursor int64 = 0
	first := true
	for first || cursor != 0 {
		first = false
		nextCursor, keys, err := client.Scan(cursor, revocationKey("*"), 0).Result()
		if err != nil {
			return errors.Wrap(err, 0)
		}
		cursor = nextCursor
		if len(keys) > 0 {
			values, err := client.MGet(keys...).Result()
			if err != nil {
				return errors.Wrap(err, 0)
			}
			for _, value := range values {
				if encodedRevocation, ok := value.(string); ok {
					if err := r.decodeAndAddRevocation(encodedRevocation); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func (r *redisRevocationsListener) decodeAndFillGaps(encoded string) error {
	currentVersion := atomic.LoadUint64(&r.lastVersion)

	parts := strings.Split(encoded, ";")
	newVersion, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return err
	}

	client, err := r.connector.getClient(keyRevocationVersionCounter)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	for version := currentVersion + 1; version < newVersion; version++ {
		r.logger.Debugf("Fetch gaps from %d", version)

		encoded, err := client.Get(revocationKey(strconv.FormatUint(version, 10))).Result()
		if err == redis.Nil {
			r.logger.Debugf("Version %d does not exists in redis", version)
		} else if err != nil {
			r.logger.ErrorErr(err)
		} else {
			if err := r.decodeAndAddRevocation(encoded); err != nil {
				r.logger.ErrorErr(err)
			}
		}
	}

	return r.decodeAndAddRevocation(encoded)
}

func (r *redisRevocationsListener) decodeAndAddRevocation(encoded string) error {
	parts := strings.Split(encoded, ";")
	if len(parts) != 3 {
		return errors.Errorf("Invalid entry: %s", encoded)
	}
	sha256, err := common.RawSha256FromBase64(parts[0])
	if err != nil {
		return err
	}
	expiresAt, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return err
	}
	version, err := strconv.ParseUint(parts[2], 10, 64)
	if err != nil {
		return err
	}

	currentVersion := atomic.LoadUint64(&r.lastVersion)
	if version > currentVersion {
		atomic.CompareAndSwapUint64(&r.lastVersion, currentVersion, version)
	}
	r.listener(version, sha256, time.Unix(expiresAt, 0))
	return nil
}

func (r *redisRevocationsListener) listenRevocationUpdates() error {
	client, err := r.connector.getClient(keyRevocationVersionCounter)
	if err != nil {
		return err
	}
	subscription, err := client.Subscribe(keyRevocationsPublish)
	if err != nil {
		return err
	}

	for {
		if message, err := subscription.ReceiveMessage(); err == nil {
			r.logger.Debugf("Received revocation update: %s", message.Payload)
			if err := r.decodeAndFillGaps(message.Payload); err != nil {
				r.logger.ErrorErr(err)
			}
		} else {
			return err
		}
	}
}

func (r *redisRevocationsListener) startListenRevocationUpdates() {
	for {
		r.logger.Info("Connect to revocation subscription")

		if err := r.listenRevocationUpdates(); err != nil {
			r.logger.ErrorErr(err)
		}
		r.logger.Info("Wait 1 second before reconnecting")
		time.Sleep(1 * time.Second)
	}
}
