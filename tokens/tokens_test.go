package tokens_test

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/tokens"
	"testing"
	"time"
)

func assertNoError(t *testing.T, err error) {
	if err != nil {
		t.Errorf("Test failed: %s", err.Error())
	}
}

func assertEquals(t *testing.T, x interface{}, y interface{}) {
	if x != y {
		t.Errorf("Test failed: %s != %s", x, y)
	}
}

func TestCreateToken(t *testing.T) {
	cert, err := certificates.NewCertWithKey("test")
	tokeninfo, err := tokens.NewTokenInfo("test", "user", time.Now(), cert)
	assertNoError(t, err)
	assertRawTokenInfo(t, tokeninfo.Raw, cert)
	assertEquals(t, tokeninfo.X5T, cert.Thumbprint)
}

func assertRawTokenInfo(t *testing.T, tokeninfo string, cert *certificates.CertWithKey) {
	handler := func(token *jwt.Token) (interface{}, error) {
		return cert.Certificate.PublicKey, nil
	}
	result, err := jwt.Parse(tokeninfo, handler)
	assertNoError(t, err)
	x5t := result.Header["x5t"]
	assertEquals(t, x5t, cert.Thumbprint)
}
