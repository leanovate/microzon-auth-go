package revocations

import (
	"github.com/leanovate/microzon-auth-go/common"
	"time"
)

type RevocationVO struct {
	Sha256    common.RawSha256 `json:"sha256"`
	ExpiresAt int64            `json:"expires_at"`
}

func NewRevokationVO(sha256 common.RawSha256, expiresAt time.Time) *RevocationVO {
	return &RevocationVO{
		Sha256:    sha256,
		ExpiresAt: expiresAt.Unix(),
	}
}
