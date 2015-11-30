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
	certWithKey, err := t.store.SelfCertificate()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(time.Duration(t.config.TokenTTL) * time.Second)
	return newTokenInfo(realm, subject, expiresAt, certWithKey)
}

func (t *TokenManager) RefreshToken(token *jwt.Token) (interface{}, error) {
	certWithKey, err := t.store.SelfCertificate()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(t.config.TokenTTL)
	return refreshToken(token, expiresAt, certWithKey)
}

func (t *TokenManager) RevokeToken(token *jwt.Token) (interface{}, error) {
	sha256 := revocations.RawSha256FromData(token.Raw)
	expiresAt := time.Unix((int64)(token.Claims[jwtClaimExpiresAt].(float64)), 0)
	return nil, t.store.AddRevocation(sha256, expiresAt)
}

func (r *TokenManager) TokenHandler(token *jwt.Token) (interface{}, error) {
	r.logger.Debugf("Token: %v", token)
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
			return nil, errors.Errorf("Certificate not found: %s", x5t)
		} else if cert.NotAfter.Before(time.Now()) {
			return nil, errors.Errorf("Certificate is expired: %s", x5t)
		} else {
			return cert.PublicKey, nil
		}
	} else {
		return nil, errors.New("No x5t field found in token")
	}
}

func (r *TokenManager) verifyRevocations(token *jwt.Token) error {
	sha256 := revocations.RawSha256FromData(token.Raw)
	revoked, err := r.store.IsRevoked(sha256)
	if err != nil {
		return err
	}
	if revoked {
		return errors.Errorf("Token has been revoked: %s", sha256.String())
	}
	return nil
}
