package redis_backend

import "fmt"

func revokationKey(sha256 string) string {
	return fmt.Sprintf("revokation:%s", sha256)
}
