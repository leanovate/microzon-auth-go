package revocations

import (
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"time"
)

// Cache/manage revocations
type RevocationsManager struct {
	*RevocationsValidator
	revocationsByVersion *versionWheel
	serverStore          store.ServerStore
}

// Create a new revocations cache
// Usually there should only be one
func NewRevocationsManager(store store.ServerStore, parent logging.Logger) (*RevocationsManager, error) {
	revocations := &RevocationsManager{
		RevocationsValidator: NewRevocationsValidator(store, parent),
		revocationsByVersion: newVersionWheel(17),
		serverStore:          store,
	}
	go revocations.StartCleanup()

	if err := store.SetRevocationsListener(revocations.onNewRevocation); err != nil {
		return nil, err
	}

	return revocations, nil
}

// Add a revocation
func (r *RevocationsManager) AddRevocation(sha256 common.RawSha256, expiresAt time.Time) error {
	return r.serverStore.AddRevocation(sha256, expiresAt)
}

// Get all revocations since a given version
func (r *RevocationsManager) GetRevocationsSinceVersion(version uint64, maxLength int) *RevocationListVO {
	r.lock.RLock()
	defer r.lock.RUnlock()

	maxVersion := r.revocationsByVersion.lastVersion

	result := make([]*RevocationVO, 0, maxLength)
	revocation := r.revocationsByVersion.next(version)
	for revocation != nil {
		result = append(result, revocation)
		if len(result) >= maxLength {
			return NewRevocationListVO(revocation.Version, result)
		}
		revocation = r.revocationsByVersion.next(revocation.Version)
	}

	return NewRevocationListVO(maxVersion, result)
}

func (r *RevocationsManager) CurrentVersion() uint64 {
	r.lock.RLock()
	r.lock.RUnlock()

	return r.revocationsByVersion.lastVersion
}

// Cleanup expired revocations
func (r *RevocationsManager) cleanup() {
	r.logger.Debug("Do cleanup")
	expiredRevocations := r.expirationTimeWheel.getExpiredRevocations(time.Now())

	if len(expiredRevocations) == 0 {
		r.logger.Debug("Nothing to cleanup")
		return
	}
	r.lock.Lock()
	defer r.lock.Unlock()

	r.logger.Debugf("Cleaning up %d revocations", len(expiredRevocations))
	for _, revocation := range expiredRevocations {
		r.revocationHashes.removeHash(revocation.Sha256)
		r.revocationsByVersion.removeVersion(revocation.Version)
	}
}

func (r *RevocationsManager) StartCleanup() {
	r.logger.Debug("Start cleanup loop")
	for {
		diff := time.Now().Unix() - r.expirationTimeWheel.lastCleanup
		if diff <= 0 {
			time.Sleep(1 * time.Second)
		}
		r.cleanup()
	}
}

func (r *RevocationsManager) onNewRevocation(version uint64, sha256 common.RawSha256, expiresAt time.Time) {
	revocation := NewRevokationVO(version, sha256, expiresAt)

	r.lock.Lock()
	triggerNotify := false
	if version > r.revocationsByVersion.lastVersion {
		triggerNotify = true
	}
	r.revocationHashes.addRevocation(revocation)
	r.revocationsByVersion.addRevocation(revocation)
	r.lock.Unlock()
	r.expirationTimeWheel.AddEntry(revocation)
	if triggerNotify {
		r.Observe.Notify(ObserveState(version))
	}
}
