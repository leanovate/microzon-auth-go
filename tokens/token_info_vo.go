package tokens

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/certificates"
	"time"
)

type TokenInfoVO struct {
	Raw       string `json:"raw"`
	Realm     string `json:"realm"`
	Subject   string `json:"sub"`
	ExpiresAt int64  `json:"exp"`
	X5T       string `json:"x5t"`
	Sha256    string `json:"sha256"`
}

func NewTokenInfo(realm, subject string, expiresAt time.Time, signer *certificates.CertWithKey) (*TokenInfoVO, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Header["x5t"] = signer.Thumbprint
	token.Claims["exp"] = expiresAt.Unix()
	token.Claims["sub"] = subject
	token.Claims["realm"] = realm

	raw, err := token.SignedString(signer.PrivateKey)

	if err != nil {
		return nil, errors.Wrap(err, 0)
	}

	return &TokenInfoVO{
		Raw:       raw,
		Realm:     realm,
		Subject:   subject,
		ExpiresAt: expiresAt.Unix(),
		X5T:       signer.Thumbprint,
		Sha256:    toSha256(raw),
	}, nil
}

func CopyFromToken(token *jwt.Token) (interface{}, error) {
	return &TokenInfoVO{
		Raw:       token.Raw,
		Realm:     token.Claims["realm"].(string),
		Subject:   token.Claims["sub"].(string),
		ExpiresAt: (int64)(token.Claims["exp"].(float64)),
		X5T:       token.Header["x5t"].(string),
		Sha256:    toSha256(token.Raw),
	}, nil
}

func RefreshToken(token *jwt.Token, expirationTime time.Time, signer *certificates.CertWithKey) (interface{}, error) {
	return NewTokenInfo(token.Claims["realm"].(string), token.Claims["sub"].(string), expirationTime, signer)
}

func toSha256(raw string) string {
	sha := sha256.New()
	sha.Write([]byte(raw))
	return base64.URLEncoding.EncodeToString(sha.Sum(nil))
}
