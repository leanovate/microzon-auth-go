package tokens

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/leanovate/microzon-auth-go/certificates"
	"time"
)

func NewToken(signer *certificates.CertWithKey) (string, error) {
	token := jwt.New(jwt.SigningMethodRS256)
	token.Claims["ski"] = signer.Ski
	token.Claims["exp"] = time.Now().Add(time.Hour * 72).Unix()

	return token.SignedString(signer.PrivateKey)
}
