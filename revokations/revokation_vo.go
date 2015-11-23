package revokations

import "time"

type RevokationVO struct {
	Version   uint64 `json:"-"`
	Sha256    string `json:"sha256"`
	ExpiresAt int64  `json:"expires_at"`
}

func NewRevokationVO(version uint64, sha256 string, expiresAt time.Time) *RevokationVO {
	return &RevokationVO{
		Version:   version,
		Sha256:    sha256,
		ExpiresAt: expiresAt.Unix(),
	}
}
