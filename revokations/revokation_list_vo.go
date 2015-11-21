package revokations

type RevokationListVO struct {
	Version     uint64          `json:"version"`
	Revokations []*RevokationVO `json:"revokations"`
}

func NewRevokationListVO(version uint64, revokations []*RevokationVO) *RevokationListVO {
	return &RevokationListVO{
		Version:     version,
		Revokations: revokations,
	}
}
