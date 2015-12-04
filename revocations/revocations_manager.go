package revocations

import (
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"time"
)

// Cache/manage revocations
type RevocationsManager struct {
	Observe              *ObserverGroup
	logger               logging.Logger
	revocationHashes     *hashWheel
	revocationsByVersion *versionWheel
	expirationTimeWheel  *timeWheel
	agentStore           store.AgentStore
}

// Create a new revocations cache
// Usually there should only be one
func NewRevocationsManager(store store.AgentStore, parent logging.Logger) (*RevocationsManager, error) {
	revocations := &RevocationsManager{
		Observe:              NewObserverGroup(0, parent),
		logger:               parent.WithContext(map[string]interface{}{"package": "revokations"}),
		revocationHashes:     newHashWheel(),
		revocationsByVersion: newVersionWheel(),
		expirationTimeWheel:  newTimeWheel(600),
		agentStore:           store,
	}
	go revocations.StartCleanup()

	if err := store.SetRevocationsListener(revocations.onNewRevocation); err != nil {
		return nil, err
	}

	return revocations, nil
}

// Check if a token hash is contained in the revocations
// I.e. check if the token has been revoked
func (r *RevocationsManager) IsRevoked(sha256 common.RawSha256) bool {
	return r.revocationHashes.containsHash(sha256)
}

// Get all revocations since a given version
func (r *RevocationsManager) GetRevocationsSinceVersion(version uint64, maxLength int) *RevocationListVO {
	maxVersion := r.revocationsByVersion.getLastVersion()

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
	return r.revocationsByVersion.getLastVersion()
}

// Cleanup expired revocations
func (r *RevocationsManager) cleanup() {
	r.logger.Debug("Do cleanup")
	expiredRevocations := r.expirationTimeWheel.getExpiredRevocations(time.Now())

	if len(expiredRevocations) == 0 {
		r.logger.Debug("Nothing to cleanup")
		return
	}

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
	r.revocationHashes.addRevocation(revocation)
	r.revocationsByVersion.addRevocation(revocation)
	r.expirationTimeWheel.AddEntry(revocation)
	lastVersion := r.revocationsByVersion.getLastVersion()
	if ObserveState(lastVersion) > r.Observe.state {
		r.Observe.Notify(ObserveState(lastVersion))
	}
}
