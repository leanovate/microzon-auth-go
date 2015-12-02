package common

import "time"

type RevocationsListener func(version uint64, sha256 RawSha256, expiresAt time.Time)
