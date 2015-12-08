package tokens

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"time"
)

type TokenManager struct {
	*TokenValidator
	signerCertificateManager *certificates.CertificateManager
	revocationsManager       *revocations.RevocationsManager
}

func NewTokenManager(config *config.TokenConfig, certificateManager *certificates.CertificateManager,
	revocationsManager *revocations.RevocationsManager, parent logging.Logger) *TokenManager {

	return &TokenManager{
		TokenValidator:           NewTokenValidator(config, certificateManager.CertificateValidator, revocationsManager.RevocationsValidator, parent),
		signerCertificateManager: certificateManager,
		revocationsManager:       revocationsManager,
	}
}

func (t *TokenManager) CreateToken(realm, subject string) (*TokenInfoVO, error) {
	certWithKey, err := t.signerCertificateManager.GetSelfCertificate()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(t.TokenValidator.config.TokenTTL)
	return newTokenInfo(realm, subject, expiresAt, certWithKey)
}

func (t *TokenManager) RefreshToken(token *jwt.Token) (interface{}, error) {
	certWithKey, err := t.signerCertificateManager.GetSelfCertificate()
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(t.TokenValidator.config.TokenTTL)
	return refreshToken(token, expiresAt, certWithKey)
}

func (t *TokenManager) RevokeToken(token *jwt.Token) (interface{}, error) {
	sha256 := common.RawSha256FromData(token.Raw)
	expiresAt := time.Unix((int64)(token.Claims[jwtClaimExpiresAt].(float64)), 0)
	return nil, t.revocationsManager.AddRevocation(sha256, expiresAt)
}
