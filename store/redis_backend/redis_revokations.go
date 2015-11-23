package redis_backend

import (
	"fmt"
	"strconv"
	"time"
)

const insertRevocationScript = `
local version = redis.call("INCR", KEYS[1])
redis.call("HMSET", "revocations:version:" .. version, "sha256", ARGV[1], "expiresAt", ARGV[2], "version", version)
redis.call("EXPIRE", "revocations:version:" .. version, ARGV[3])
redis.call("PUBLISH", "revocations", version)
return version
`

const keyRevocationVersionCounter = "revocations:version"

func (r *redisStore) insertRevocation(sha256 string, expiresAt time.Time) error {
	expiresAtUnix := expiresAt.Unix()
	expiration := int64(expiresAt.Sub(time.Now()) / time.Second)
	result, err := r.redisClient.Eval(insertRevocationScript, []string{keyRevocationVersionCounter},
		[]string{sha256, strconv.FormatInt(expiresAtUnix, 10), strconv.FormatInt(expiration, 10)}).Result()

	if err != nil {
		return err
	}

	fmt.Printf("%v", result)
	return nil
}
