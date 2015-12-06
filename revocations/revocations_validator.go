package revocations

import (
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"sync"
)

type RevocationsValidator struct {
	Observe             *ObserverGroup
	lock                sync.RWMutex
	logger              logging.Logger
	revocationHashes    *hashWheel
	expirationTimeWheel *timeWheel
	agentStore          store.AgentStore
}

func NewRevocationsValidator(store store.AgentStore, parent logging.Logger) *RevocationsValidator {
	return &RevocationsValidator{
		Observe:             NewObserverGroup(0, parent),
		logger:              parent.WithContext(map[string]interface{}{"package": "revokations"}),
		revocationHashes:    newHashWheel(17),
		expirationTimeWheel: newTimeWheel(600),
		agentStore:          store,
	}
}

// Check if a token hash is contained in the revocations
// I.e. check if the token has been revoked
func (r *RevocationsValidator) IsRevoked(sha256 common.RawSha256) bool {
	r.lock.RLock()
	defer r.lock.RUnlock()

	return r.revocationHashes.containsHash(sha256)
}
