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
	logger               logging.Logger
	revocationHashes     map[RawSha256]bool
	revocationsByVersion *skiplist.SkipList
	expirationTimeWheel  *timeWheel
	maxVersion           uint64
}

// Create a new revocations cache
// Usually there should only be one
func NewRevokations(parent logging.Logger) *Revocations {
	return &Revocations{
		Observe:          NewObserverGroup(0, parent),
		logger:           parent.WithContext(map[string]interface{}{"package": "revokations"}),
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
	r.revocationHashes[sha256] = true
	r.revocationsByVersion.Set(version, NewRevokationVO(sha256, expiresAt))
	triggerNotify := false
	if version > r.maxVersion {
		r.maxVersion = version
		triggerNotify = true
	}
	r.lock.Unlock()
	r.expirationTimeWheel.AddEntry(expiresAt, version)
	if triggerNotify {
		r.Observe.Notify(ObserveState(version))
	}
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
func (r *Revocations) GetRevocationsSinceVersion(version uint64) *RevocationListVO {
	r.lock.RLock()
	defer r.lock.RUnlock()

	result := make([]*RevocationVO, 0)
	iterator := r.revocationsByVersion.Iterator()
	valid := iterator.Seek(version + 1)
	for valid {
		result = append(result, iterator.Value().(*RevocationVO))
		valid = iterator.Next()
	}

	return NewRevocationListVO(r.maxVersion, result)
}

func (r *Revocations) CurrentVersion() uint64 {
	return r.maxVersion
}

// Cleanup expired revocations
func (r *Revocations) cleanup() {
	r.logger.Debug("Do cleanup")
	expiredVersions := r.expirationTimeWheel.GetExpiredVersions(time.Now())

	if len(expiredVersions) == 0 {
		r.logger.Debug("Nothing to cleanup")
		return
	}
	r.lock.Lock()
	defer r.lock.Unlock()

	r.logger.Debugf("Cleaning up %d revocations", len(expiredVersions))
	for _, version := range expiredVersions {
		if deleted, ok := r.revocationsByVersion.Delete(version); ok {
			delete(r.revocationHashes, deleted.(*RevocationVO).Sha256)
		}
	}
}

func (r *Revocations) StartCleanup() {
	r.logger.Debug("Start cleanup loop")
	for {
		diff := time.Now().Unix() - r.expirationTimeWheel.lastCleanup
		if diff <= 0 {
			time.Sleep(1 * time.Second)
		}
		r.cleanup()
	}
}
