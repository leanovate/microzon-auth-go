package revocations

import (
	"sync"
)

const (
	versionWheelSize = 0x20000
	versionWheelMask = 0x1ffff
)

type versionWheelNode []*RevocationVO

func (v *versionWheelNode) addRevocation(revocation *RevocationVO) {
	*v = append(*v, revocation)
}

func (v versionWheelNode) getVersion(version uint64) *RevocationVO {
	for _, revocation := range v {
		if revocation.Version == version {
			return revocation
		}
	}
	return nil
}

func (v *versionWheelNode) removeVersion(version uint64) {
	for i, revocation := range *v {
		if revocation.Version == version {
			if 2*len(*v) < cap(*v) {
				*v = append(make(versionWheelNode, 0, len(*v)-1), (*v)[:i]...)
				*v = append(*v, (*v)[i+1:]...)
			} else {
				*v, (*v)[len(*v)-1] = append((*v)[:i], (*v)[i+1:]...), nil
			}
			return
		}
	}
}

func (v versionWheelNode) nextCandidate(version uint64) *RevocationVO {
	// The list is implicitly ordered
	for _, revocation := range v {
		if revocation.Version > version {
			return revocation
		}
	}
	return nil
}

type versionWheel struct {
	lock        sync.RWMutex
	lastVersion uint64
	wheel       []versionWheelNode
}

func newVersionWheel() *versionWheel {
	return &versionWheel{
		lastVersion: 0,
		wheel:       make([]versionWheelNode, versionWheelSize),
	}
}

func (w *versionWheel) calculateIndex(version uint64) uint32 {
	return uint32(version & versionWheelMask)
}

func (w *versionWheel) addRevocation(revocation *RevocationVO) {
	index := w.calculateIndex(revocation.Version)

	w.lock.Lock()
	defer w.lock.Unlock()

	w.wheel[index].addRevocation(revocation)

	if w.lastVersion < revocation.Version {
		w.lastVersion = revocation.Version
	}
}

func (w *versionWheel) getVersion(version uint64) *RevocationVO {
	index := w.calculateIndex(version)

	w.lock.RLock()
	defer w.lock.RUnlock()

	return w.wheel[index].getVersion(version)
}

func (w *versionWheel) removeVersion(version uint64) {
	index := w.calculateIndex(version)

	w.lock.Lock()
	defer w.lock.Unlock()

	w.wheel[index].removeVersion(version)
}

func (w *versionWheel) next(version uint64) *RevocationVO {
	w.lock.RLock()
	defer w.lock.RUnlock()

	if version >= w.lastVersion {
		return nil
	}
	var candidate *RevocationVO
	index := w.calculateIndex(version)
	for i := uint32(0); i < versionWheelSize; i++ {
		if nextCandidate := w.wheel[(index+i)&versionWheelMask].nextCandidate(version); nextCandidate != nil {
			// this only works since versions come in an ordered manner with little to no gaps
			if nextCandidate.Version < version+versionWheelSize {
				return nextCandidate
			}
			if candidate == nil || nextCandidate.Version < candidate.Version {
				candidate = nextCandidate
			}
		}
	}

	return candidate
}

func (w *versionWheel) getLastVersion() uint64 {
	w.lock.RLock()
	defer w.lock.RUnlock()

	return w.lastVersion
}

func (w *versionWheel) count() int {
	w.lock.RLock()
	defer w.lock.RUnlock()

	count := 0
	for _, node := range w.wheel {
		count += len(node)
	}
	return count
}
