package revocations

import "time"

type RevocationVO struct {
	Sha256    RawSha256 `json:"sha256"`
	ExpiresAt int64     `json:"expires_at"`
}

func NewRevokationVO(sha256 RawSha256, expiresAt time.Time) *RevocationVO {
	return &RevocationVO{
		Sha256:    sha256,
		ExpiresAt: expiresAt.Unix(),
	}
}
