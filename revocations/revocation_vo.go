package revocations

type RevocationVO struct {
	Sha256    string `json:"sha256"`
	ExpiresAt int64  `json:"expires_at"`
}

func NewRevokationVO(revocation *Revocation) *RevocationVO {
	return &RevocationVO{
		Sha256:    revocation.Sha256.String(),
		ExpiresAt: revocation.ExpiresAt.Unix(),
	}
}
