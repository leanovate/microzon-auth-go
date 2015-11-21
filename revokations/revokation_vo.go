package revokations

type RevokationVO struct {
	Sha256    string `json:"sha256"`
	ExpiresAt int64  `json:"expires_at"`
}

func NewRevokationVO(sha256 string, expiresAt int64) *RevokationVO {
	return &RevokationVO{
		Sha256:    sha256,
		ExpiresAt: expiresAt,
	}
}
