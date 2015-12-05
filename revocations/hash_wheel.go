package revocations

import (
	"github.com/leanovate/microzon-auth-go/common"
	"sync"
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
			(*v)[i] = (*v)[len(*v)-1]
			if 2*len(*v) < cap(*v) {
				*v = append(hashWheelNode(nil), (*v)[:len(*v)-1]...)
			} else {
				(*v)[len(*v)-1] = nil
				*v = (*v)[:len(*v)-1]
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
	lock  sync.RWMutex
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

	w.lock.Lock()
	defer w.lock.Unlock()

	w.wheel[index].addRevocation(revocation)
}

func (w *hashWheel) removeHash(hash common.RawSha256) {
	index := w.calculateIndex(hash)

	w.lock.Lock()
	defer w.lock.Unlock()

	w.wheel[index].removeHash(hash)
}

func (w *hashWheel) containsHash(hash common.RawSha256) bool {
	index := w.calculateIndex(hash)

	w.lock.RLock()
	defer w.lock.RUnlock()

	return w.wheel[index].containsHash(hash)
}

func (w *hashWheel) count() int {
	w.lock.RLock()
	defer w.lock.RUnlock()

	count := 0
	for _, node := range w.wheel {
		count += len(node)
	}
	return count
}