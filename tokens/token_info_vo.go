package tokens

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/revocations"
	"github.com/satori/go.uuid"
	"time"
)

type TokenInfoVO struct {
	Raw       string                `json:"raw"`
	Id        string                `json:"id"`
	Realm     string                `json:"realm"`
	Subject   string                `json:"sub"`
	ExpiresAt int64                 `json:"exp"`
	X5T       string                `json:"x5t"`
	Sha256    revocations.RawSha256 `json:"sha256"`
}

const (
	jwtHeaderThumbprint = "x5t"
	jwtClaimRealm       = "realm"
	jwtClaimSubject     = "sub"
	jwtClaimExpiresAt   = "exp"
	jwtClaimId          = "jti"
)

func newTokenInfo(realm, subject string, expiresAt time.Time, signer *certificates.CertWithKey) (*TokenInfoVO, error) {
	id := uuid.NewV1().String()
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header[jwtHeaderThumbprint] = signer.Thumbprint
	token.Claims[jwtClaimExpiresAt] = expiresAt.Unix()
	token.Claims[jwtClaimSubject] = subject
	token.Claims[jwtClaimRealm] = realm
	token.Claims[jwtClaimId] = id

	raw, err := token.SignedString(signer.PrivateKey)

	if err != nil {
		return nil, errors.Wrap(err, 0)
	}

	return &TokenInfoVO{
		Raw:       raw,
		Id:        id,
		Realm:     realm,
		Subject:   subject,
		ExpiresAt: expiresAt.Unix(),
		X5T:       signer.Thumbprint,
		Sha256:    revocations.RawSha256FromData(raw),
	}, nil
}

func CopyFromToken(token *jwt.Token) (interface{}, error) {
	return &TokenInfoVO{
		Raw:       token.Raw,
		Id:        token.Claims[jwtClaimId].(string),
		Realm:     token.Claims[jwtClaimRealm].(string),
		Subject:   token.Claims[jwtClaimSubject].(string),
		ExpiresAt: (int64)(token.Claims[jwtClaimExpiresAt].(float64)),
		X5T:       token.Header[jwtHeaderThumbprint].(string),
		Sha256:    revocations.RawSha256FromData(token.Raw),
	}, nil
}

func refreshToken(token *jwt.Token, expirationTime time.Time, signer *certificates.CertWithKey) (*TokenInfoVO, error) {
	return newTokenInfo(token.Claims[jwtClaimRealm].(string), token.Claims[jwtClaimSubject].(string), expirationTime, signer)
}
