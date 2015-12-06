package revocations

import (
	"github.com/leanovate/microzon-auth-go/common"
)

const (
	hashWheelSize = 0x20000
	hashWheelMask = 0x1ffff
)

type hashWheelNode []*RevocationVO

func (v *hashWheelNode) addRevocation(revocation *RevocationVO) {
	*v = append(*v, revocation)
}

func (v *hashWheelNode) removeHash(hash common.RawSha256) {
	for i, revocation := range *v {
		if revocation.Sha256 == hash {
			n := len(*v)
			(*v)[i] = (*v)[n-1]
			(*v)[n-1] = nil
			if 2*n < cap(*v) {
				*v = append(hashWheelNode(nil), (*v)[:n-1]...)
			} else {
				*v = (*v)[:n-1]
			}
			return
		}
	}
}

func (v hashWheelNode) containsHash(hash common.RawSha256) bool {
	for _, revocation := range v {
		if revocation.Sha256 == hash {
			return true
		}
	}
	return false
}

// Actually this is not much more than a classic hash map
// But since we already have two other wheels so a third one will not hurt
type hashWheel struct {
	wheel []hashWheelNode
}

func newHashWheel() *hashWheel {
	return &hashWheel{
		wheel: make([]hashWheelNode, hashWheelSize),
	}
}

func (w *hashWheel) calculateIndex(hash common.RawSha256) uint32 {
	index := uint32(0)
	for _, value := range hash {
		index ^= uint32(value)
		index <<= 1
	}
	return index & hashWheelMask
}

func (w *hashWheel) addRevocation(revocation *RevocationVO) {
	index := w.calculateIndex(revocation.Sha256)

	w.wheel[index].addRevocation(revocation)
}

func (w *hashWheel) removeHash(hash common.RawSha256) {
	index := w.calculateIndex(hash)

	w.wheel[index].removeHash(hash)
}

func (w *hashWheel) containsHash(hash common.RawSha256) bool {
	index := w.calculateIndex(hash)

	return w.wheel[index].containsHash(hash)
}

func (w *hashWheel) count() int {
	count := 0
	for _, node := range w.wheel {
		count += len(node)
	}
	return count
}
