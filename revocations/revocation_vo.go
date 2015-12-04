package revocations

import (
	"github.com/leanovate/microzon-auth-go/common"
	"time"
)

type RevocationVO struct {
	Version   uint64           `json:"version"`
	Sha256    common.RawSha256 `json:"sha256"`
	ExpiresAt int64            `json:"expires_at"`
}

func NewRevokationVO(version uint64, sha256 common.RawSha256, expiresAt time.Time) *RevocationVO {
	return &RevocationVO{
		Version:   version,
		Sha256:    sha256,
		ExpiresAt: expiresAt.Unix(),
	}
}
