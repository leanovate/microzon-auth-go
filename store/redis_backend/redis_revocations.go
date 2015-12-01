package redis_backend

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/revocations"
	"gopkg.in/redis.v3"
	"strconv"
	"strings"
	"time"
)

const insertRevocationScript = `
local version = redis.call("INCR", KEYS[1])
redis.call("SETEX", "revocations:version:" .. version, ARGV[3],  ARGV[1] .. ";" .. ARGV[2] .. ";" .. version)
redis.call("PUBLISH", KEYS[2], version)
return version
`

const keyRevocationsPublish = "revocations"
const keyRevocationVersionCounter = "revocations:version"

func revocationKey(version string) string {
	return fmt.Sprintf("revocations:version:%s", version)
}

func (r *redisStore) scanRevocations() error {
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
			encodedRevocations, err := client.MGet(keys...).Result()
			if err != nil {
				return errors.Wrap(err, 0)
			}
			for _, encodedRevocation := range encodedRevocations {
				if err := r.decodeAndAddRevocation(encodedRevocation.(string)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (r *redisStore) insertRevocation(sha256 revocations.RawSha256, expiresAt time.Time) error {
	client, err := r.connector.getClient(keyRevocationVersionCounter)
	if err != nil {
		return errors.Wrap(err, 0)
	}
	expiresAtUnix := expiresAt.Unix()
	expiration := int64(expiresAt.Sub(time.Now()) / time.Second)
	result, err := client.Eval(insertRevocationScript,
		[]string{keyRevocationVersionCounter, keyRevocationsPublish},
		[]string{sha256.String(), strconv.FormatInt(expiresAtUnix, 10), strconv.FormatInt(expiration, 10)}).Result()

	if err != nil {
		return err
	}
	r.logger.Debugf("Stored revocation sha256=%s version=%v", sha256.String(), result)

	return nil
}

func (r *redisStore) fetchUpdates(newVersion uint64) error {
	client, err := r.connector.getClient(keyRevocationVersionCounter)
	if err != nil {
		return errors.Wrap(err, 0)
	}

	currentVersion := r.revocations.CurrentVersion()
	r.logger.Debugf("Fetch updates from %d to %d", currentVersion, newVersion)

	for version := currentVersion + 1; version <= newVersion; version++ {
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
	return nil
}

func (r *redisStore) decodeAndAddRevocation(encoded string) error {
	parts := strings.Split(encoded, ";")
	if len(parts) != 3 {
		return errors.Errorf("Invalid entry: %s", encoded)
	}
	sha256, err := revocations.RawSha256FromBase64(parts[0])
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

	r.revocations.AddRevocation(version, sha256, time.Unix(expiresAt, 0))
	return nil
}

func (r *redisStore) listenRevocationUpdates() error {
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
			if version, err := strconv.ParseUint(message.Payload, 10, 64); err == nil {
				if err := r.fetchUpdates(version); err != nil {
					r.logger.ErrorErr(err)
				}
			} else {
				r.logger.ErrorErr(err)
			}
		} else {
			return err
		}
	}
}

func (r *redisStore) startListenRevocationUpdates() {
	for {
		r.logger.Info("Connect to revocation subscription")

		if err := r.listenRevocationUpdates(); err != nil {
			r.logger.ErrorErr(err)
		}
		r.logger.Info("Wait 1 second before reconnecting")
		time.Sleep(1 * time.Second)
	}
}
