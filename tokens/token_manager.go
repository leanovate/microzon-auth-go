package tokens

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"time"
)

type TokenManager struct {
	logger logging.Logger
	config *config.TokenConfig
	store  store.Store
}

func NewTokenManager(config *config.TokenConfig, store store.Store, parent logging.Logger) *TokenManager {

	return &TokenManager{
		logger: parent.WithContext(map[string]interface{}{"package": "tokens"}),
		config: config,
		store:  store,
	}
}

func (t *TokenManager) CreateToken(realm, subject string) (*TokenInfoVO, error) {
	expiresAt := time.Now().Add(time.Duration(t.config.TokenTTL) * time.Second)
	return newTokenInfo(realm, subject, expiresAt, t.store.SelfCertificate())
}

func (t *TokenManager) RefreshToken(token *jwt.Token) (*TokenInfoVO, error) {
	expiresAt := time.Now().Add(time.Duration(t.config.TokenTTL) * time.Second)
	return refreshToken(token, expiresAt, t.store.SelfCertificate())
}
