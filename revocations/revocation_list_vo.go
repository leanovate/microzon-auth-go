package revocations

type RevocationListVO struct {
	Version     uint64          `json:"version"`
	Revocations []*RevocationVO `json:"revocations"`
}

func NewRevocationListVO(version uint64, revokations []*RevocationVO) *RevocationListVO {
	return &RevocationListVO{
		Version:     version,
		Revocations: revokations,
	}
}
