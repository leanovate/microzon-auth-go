package tokens

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
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

func (t *TokenManager) RefreshToken(token *jwt.Token) (interface{}, error) {
	expiresAt := time.Now().Add(time.Duration(t.config.TokenTTL) * time.Second)
	return refreshToken(token, expiresAt, t.store.SelfCertificate())
}

func (t *TokenManager) RevokeToken(token *jwt.Token) (interface{}, error) {
	sha256 := revocations.RawSha256FromData(token.Raw)
	expiresAt := time.Unix((int64)(token.Claims[jwtClaimExpiresAt].(float64)), 0)
	return nil, t.store.AddRevocation(sha256, expiresAt)
}

func (r *TokenManager) TokenHandler(token *jwt.Token) (interface{}, error) {
	r.logger.Debugf("Token: %s", *token)
	err := r.verifyRevocations(token)
	if err != nil {
		return nil, err
	} else {
		return r.verifyCertificate(token)
	}
}

func (r *TokenManager) verifyCertificate(token *jwt.Token) (interface{}, error) {
	x5t := token.Header[jwtHeaderThumbprint]
	if x5t != nil {
		if cert, err := r.store.CertificateByThumbprint(x5t.(string)); err != nil || cert == nil {
			return nil, errors.New("Certificate not found")
		} else {
			return cert.PublicKey, nil
		}
	} else {
		return nil, errors.New("No x5t field found in token")
	}
}

func (r *TokenManager) verifyRevocations(token *jwt.Token) error {
	revoked, err := r.store.IsRevoked(revocations.RawSha256FromData(token.Raw))
	if err != nil {
		return err
	}
	if revoked {
		return errors.New("Token has been revoked")
	}
	return nil
}
