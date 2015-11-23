package revocations

type RevokationListVO struct {
	Version     uint64          `json:"version"`
	Revocations []*RevocationVO `json:"revocations"`
}

func NewRevokationListVO(version uint64, revokations []*RevocationVO) *RevokationListVO {
	return &RevokationListVO{
		Version:     version,
		Revocations: revokations,
	}
}
