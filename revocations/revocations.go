package revocations

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"sync"
	"time"
)

// Cache/manage revocations
type Revocations struct {
	Observe              *ObserverGroup
	lock                 sync.RWMutex
	revocationsByHash    map[string]*RevocationVO
	revocationsByVersion map[uint64]*RevocationVO
	minVersion           uint64
	maxVersion           uint64
}

// Create a new revocations cache
// Usually there should only be one
func NewRevokations(logger logging.Logger) *Revocations {
	return &Revocations{
		Observe:              NewObserverGroup(logger),
		revocationsByHash:    make(map[string]*RevocationVO, 0),
		revocationsByVersion: make(map[uint64]*RevocationVO, 0),
		minVersion:           0,
		maxVersion:           0,
	}
}

// Add a revocation
func (r *Revocations) AddRevokation(revokation *RevocationVO) {
	r.lock.Lock()
	defer r.lock.Unlock()
	defer r.Observe.Notify()

	r.revocationsByHash[revokation.Sha256] = revokation
	r.revocationsByVersion[revokation.Version] = revokation
	if revokation.Version < r.minVersion {
		r.minVersion = revokation.Version
	}
	if revokation.Version > r.maxVersion {
		r.maxVersion = revokation.Version
	}
}

// Check if a token hash is contained in the revocations
// I.e. check if the token has been revoked
func (r *Revocations) ContainsHash(sha256 string) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()

	_, contains := r.revocationsByHash[sha256]

	return contains
}

// Get all revocations since a given version
func (r *Revocations) GetRevokationsSinceVersion(version uint64) *RevokationListVO {
	r.lock.RLock()
	defer r.lock.RUnlock()

	min := version + 1

	if min < r.minVersion {
		min = r.minVersion
	}

	result := make([]*RevocationVO, 0)
	// At this point we assume that there are little to no gaps
	for version = min; version <= r.maxVersion; version++ {
		if revokation, ok := r.revocationsByVersion[version]; ok {
			result = append(result, revokation)
		}
	}
	return NewRevokationListVO(r.maxVersion, result)
}

// Cleanup expired revocations
func (r *Revocations) cleanup() {
	expiredRevocations, newMinVersion := r.findExpired()

	if len(expiredRevocations) == 0 {
		return
	}
	r.lock.Lock()
	defer r.lock.Unlock()

	for _, revocation := range expiredRevocations {
		delete(r.revocationsByHash, revocation.Sha256)
		delete(r.revocationsByVersion, revocation.Version)
	}
	r.minVersion = newMinVersion
}

// Find find expired revocations
func (r *Revocations) findExpired() ([]*RevocationVO, uint64) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	result := make([]*RevocationVO, 0)
	newMinVersion := r.maxVersion
	now := time.Now().Unix()
	for _, revocation := range r.revocationsByHash {
		if revocation.ExpiresAt < now {
			result = append(result, revocation)
		} else if revocation.Version < newMinVersion {
			newMinVersion = revocation.Version
		}
	}
	return result, newMinVersion
}
