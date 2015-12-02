package redis_backend

import (
	"fmt"
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/common"
	"strconv"
	"time"
)

const insertRevocationScript = `
local version = redis.call("INCR", KEYS[1])
redis.call("SETEX", "revocations:version:" .. version, ARGV[3],  ARGV[1] .. ";" .. ARGV[2] .. ";" .. version)
redis.call("PUBLISH", KEYS[2], version)
return version
`

func revocationKey(version string) string {
	return fmt.Sprintf("revocations:version:%s", version)
}

func (r *redisStore) insertRevocation(sha256 common.RawSha256, expiresAt time.Time) error {
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
