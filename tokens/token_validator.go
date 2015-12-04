package tokens

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"time"
)

type TokenValidator struct {
	logger             logging.Logger
	config             *config.TokenConfig
	certificateManager *certificates.CertificateManager
	revocationsManager *revocations.RevocationsManager
}

func NewTokenValidator(config *config.TokenConfig, certificateManager *certificates.CertificateManager,
	revocationsManager *revocations.RevocationsManager, parent logging.Logger) *TokenValidator {
	return &TokenValidator{
		logger:             parent.WithContext(map[string]interface{}{"package": "tokens"}),
		config:             config,
		certificateManager: certificateManager,
		revocationsManager: revocationsManager,
	}
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

func (r *TokenValidator) verifyCertificate(token *jwt.Token) (interface{}, error) {
	x5t := token.Header[jwtHeaderThumbprint]
	if x5t != nil {
		if cert, err := r.certificateManager.FindCertificate(x5t.(string)); err != nil || cert == nil {
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
	sha256 := common.RawSha256FromData(token.Raw)
	if r.revocationsManager.IsRevoked(sha256) {
		return errors.Errorf("Token has been revoked: %s", sha256.String())
	}
	return nil
}
