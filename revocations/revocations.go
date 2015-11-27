package revocations

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/ryszard/goskiplist/skiplist"
	"sync"
	"time"
)

// Cache/manage revocations
type Revocations struct {
	Observe              *ObserverGroup
	lock                 sync.RWMutex
	revocationHashes     map[RawSha256]bool
	revocationsByVersion *skiplist.SkipList
	expirationTimeWheel  *timeWheel
	maxVersion           uint64
}

// Create a new revocations cache
// Usually there should only be one
func NewRevokations(logger logging.Logger) *Revocations {
	return &Revocations{
		Observe:          NewObserverGroup(logger),
		revocationHashes: make(map[RawSha256]bool, 0),
		revocationsByVersion: skiplist.NewCustomMap(func(l, r interface{}) bool {
			return l.(uint64) < r.(uint64)
		}),
		expirationTimeWheel: newTimeWheel(600),
		maxVersion:          0,
	}
}

// Add a revocation
func (r *Revocations) AddRevocation(version uint64, sha256 RawSha256, expiresAt time.Time) {
	r.lock.Lock()
	defer r.lock.Unlock()
	defer r.Observe.Notify()

	r.revocationHashes[sha256] = true
	r.revocationsByVersion.Set(version, NewRevokationVO(sha256, expiresAt))
	if version > r.maxVersion {
		r.maxVersion = version
	}
	r.expirationTimeWheel.AddEntry(expiresAt, version)
}

// Check if a token hash is contained in the revocations
// I.e. check if the token has been revoked
func (r *Revocations) ContainsHash(sha256 RawSha256) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()

	_, contains := r.revocationHashes[sha256]

	return contains
}

// Get all revocations since a given version
func (r *Revocations) GetRevocationsSinceVersion(version uint64) *RevokationListVO {
	r.lock.RLock()
	defer r.lock.RUnlock()

	result := make([]*RevocationVO, 0)
	iterator := r.revocationsByVersion.Iterator()
	valid := iterator.Seek(version + 1)
	for valid {
		result = append(result, iterator.Value().(*RevocationVO))
		valid = iterator.Next()
	}

	return NewRevokationListVO(r.maxVersion, result)
}

// Cleanup expired revocations
func (r *Revocations) cleanup() {
	expiredVersions := r.expirationTimeWheel.GetExpiredVersions(time.Now())

	if len(expiredVersions) == 0 {
		return
	}
	r.lock.Lock()
	defer r.lock.Unlock()

	for _, version := range expiredVersions {
		if deleted, ok := r.revocationsByVersion.Delete(version); ok {
			delete(r.revocationHashes, deleted.(*RevocationVO).Sha256)
		}
	}
}
