package redis_backend

import (
	"sync"
)

type lastVersion struct {
	lock    sync.RWMutex
	version uint64
}

func (l *lastVersion) get() uint64 {
	l.lock.RLock()
	defer l.lock.RUnlock()

	return l.version
}

func (l *lastVersion) update(version uint64) {
	l.lock.Lock()
	defer l.lock.Unlock()

	if l.version < version {
		l.version = version
	}
}
