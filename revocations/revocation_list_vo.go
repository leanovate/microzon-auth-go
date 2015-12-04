package revocations

type RevocationListVO struct {
	LastVersion uint64          `json:"last_version"`
	Revocations []*RevocationVO `json:"revocations"`
}

func NewRevocationListVO(version uint64, revokations []*RevocationVO) *RevocationListVO {
	return &RevocationListVO{
		LastVersion: version,
		Revocations: revokations,
	}
}
