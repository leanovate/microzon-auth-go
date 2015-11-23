package revokations

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"sync"
	"time"
)

// Cache/manage revokations
type Revokations struct {
	Observe              *ObserverGroup
	lock                 sync.RWMutex
	revokationsByHash    map[string]*RevokationVO
	RevokationsByVersion map[uint64]*RevokationVO
	minVersion           uint64
	maxVersion           uint64
}

// Create a new revokations cache
// Usually there should only be one
func NewRevokations(logger logging.Logger) *Revokations {
	return &Revokations{
		Observe:              NewObserverGroup(logger),
		revokationsByHash:    make(map[string]*RevokationVO, 0),
		RevokationsByVersion: make(map[uint64]*RevokationVO, 0),
		minVersion:           0,
		maxVersion:           0,
	}
}

// Add a revokation
func (r *Revokations) AddRevokation(revokation *RevokationVO) {
	r.lock.Lock()
	defer r.lock.Unlock()
	defer r.Observe.Notify()

	r.revokationsByHash[revokation.Sha256] = revokation
	r.RevokationsByVersion[revokation.Version] = revokation
	if revokation.Version < r.minVersion {
		r.minVersion = revokation.Version
	}
	if revokation.Version > r.maxVersion {
		r.maxVersion = revokation.Version
	}
}

// Check if a token hash is contained in the revokations
// I.e. check if the token has been revoked
func (r *Revokations) ContainsHash(sha256 string) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()

	_, contains := r.revokationsByHash[sha256]

	return contains
}

// Get all revokations since a given version
func (r *Revokations) GetRevokationsSinceVersion(version uint64) *RevokationListVO {
	r.lock.RLock()
	defer r.lock.RUnlock()

	min := version + 1

	if min < r.minVersion {
		min = r.minVersion
	}

	result := make([]*RevokationVO, 0)
	// At this point we assume that there are little to no gaps
	for version = min; version <= r.maxVersion; version++ {
		if revokation, ok := r.RevokationsByVersion[version]; ok {
			result = append(result, revokation)
		}
	}
	return NewRevokationListVO(r.maxVersion, result)
}

// Cleanup expired revokations
func (r *Revokations) cleanup() {
	expiredRevokations, newMinVersion := r.findExpired()

	if len(expiredRevokations) == 0 {
		return
	}
	r.lock.Lock()
	defer r.lock.Unlock()

	for _, revokation := range expiredRevokations {
		delete(r.revokationsByHash, revokation.Sha256)
		delete(r.RevokationsByVersion, revokation.Version)
	}
	r.minVersion = newMinVersion
}

// Find find expired revokations
func (r *Revokations) findExpired() ([]*RevokationVO, uint64) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	result := make([]*RevokationVO, 0)
	newMinVersion := r.maxVersion
	now := time.Now().Unix()
	for _, revokation := range r.revokationsByHash {
		if revokation.ExpiresAt < now {
			result = append(result, revokation)
		} else if revokation.Version < newMinVersion {
			newMinVersion = revokation.Version
		}
	}
	return result, newMinVersion
}
