package revocations

import "time"

type RevocationVO struct {
	Version   uint64 `json:"-"`
	Sha256    string `json:"sha256"`
	ExpiresAt int64  `json:"expires_at"`
}

func NewRevokationVO(version uint64, sha256 string, expiresAt time.Time) *RevocationVO {
	return &RevocationVO{
		Version:   version,
		Sha256:    sha256,
		ExpiresAt: expiresAt.Unix(),
	}
}
