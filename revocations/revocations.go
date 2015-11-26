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
	revocationsByHash    map[RawSha256]*Revocation
	revocationsByVersion map[uint64]*Revocation
	minVersion           uint64
	maxVersion           uint64
	minExpiresAt         time.Time
}

// Create a new revocations cache
// Usually there should only be one
func NewRevokations(logger logging.Logger) *Revocations {
	return &Revocations{
		Observe:              NewObserverGroup(logger),
		revocationsByHash:    make(map[RawSha256]*Revocation, 0),
		revocationsByVersion: make(map[uint64]*Revocation, 0),
		minVersion:           0,
		maxVersion:           0,
		minExpiresAt:         time.Now().Add(24 * time.Hour),
	}
}

// Add a revocation
func (r *Revocations) AddRevokation(revocation *Revocation) {
	r.lock.Lock()
	defer r.lock.Unlock()
	defer r.Observe.Notify()

	r.revocationsByHash[revocation.Sha256] = revocation
	r.revocationsByVersion[revocation.Version] = revocation
	if revocation.Version < r.minVersion {
		r.minVersion = revocation.Version
	}
	if revocation.Version > r.maxVersion {
		r.maxVersion = revocation.Version
	}
	if revocation.ExpiresAt.Before(r.minExpiresAt) {
		r.minExpiresAt = revocation.ExpiresAt
	}
}

// Check if a token hash is contained in the revocations
// I.e. check if the token has been revoked
func (r *Revocations) ContainsHash(sha256 RawSha256) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()

	_, contains := r.revocationsByHash[sha256]

	return contains
}

// Get all revocations since a given version
func (r *Revocations) GetRevocationsSinceVersion(version uint64) *RevokationListVO {
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
			result = append(result, NewRevokationVO(revokation))
		}
	}
	return NewRevokationListVO(r.maxVersion, result)
}

// Cleanup expired revocations
func (r *Revocations) cleanup() {
	expiredRevocations, newMinVersion, newMinExpiresAt := r.findExpired()

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
	r.minExpiresAt = newMinExpiresAt
}

// Find find expired revocations
func (r *Revocations) findExpired() ([]*Revocation, uint64, time.Time) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	result := make([]*Revocation, 0)
	newMinVersion := r.maxVersion
	now := time.Now()
	newMinExpiresAt := now.Add(24 * time.Hour)
	for _, revocation := range r.revocationsByHash {
		if revocation.ExpiresAt.Before(now) {
			result = append(result, revocation)
		} else {
			if revocation.Version < newMinVersion {
				newMinVersion = revocation.Version
			}
			if revocation.ExpiresAt.Before(newMinExpiresAt) {
				newMinExpiresAt = revocation.ExpiresAt
			}
		}
	}
	return result, newMinVersion, newMinExpiresAt
}
