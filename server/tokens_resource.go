package server

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/go-errors/errors"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/leanovate/microzon-auth-go/tokens"
	"github.com/untoldwind/routing"
	"net/http"
	"time"
)

type tokensResource struct {
	store  store.Store
	logger logging.Logger
}

func (s *Server) TokensResource() routing.Matcher {
	resource := &tokensResource{
		store:  s.store,
		logger: s.logger.WithContext(map[string]interface{}{"resource": "tokens"}),
	}
	return routing.PrefixSeq("/tokens",
		routing.EndSeq(
			routing.POSTFunc(wrap(resource.logger, resource.CreateToken)),
			routing.MethodNotAllowed,
		),
		routing.PrefixSeq("/myself",
			routing.EndSeq(
				routing.GETFunc(wrap(resource.logger, resource.VerifyToken)),
				routing.DELETEFunc(wrap(resource.logger, resource.RevokeToken)),
				routing.PUTFunc(wrap(resource.logger, resource.RefreshToken)),
				routing.MethodNotAllowed,
			),
		),
	)
}

func (r *tokensResource) CreateToken(req *http.Request) (interface{}, error) {
	selfCert, err := r.store.SelfCertificate()
	if err != nil {
		return nil, err
	} else {
		return tokens.NewTokenInfo("realm", "user", r.newExpirationTime(), selfCert)
	}
}

func (r *tokensResource) VerifyToken(req *http.Request) (interface{}, error) {
	return r.parseFromRequest(req, tokens.CopyFromToken)
}

func (r *tokensResource) RefreshToken(req *http.Request) (interface{}, error) {
	selfCert, err := r.store.SelfCertificate()
	if err != nil {
		return nil, err
	} else {
		successHandler := func(token *jwt.Token) (interface{}, error) {
			return tokens.RefreshToken(token, r.newExpirationTime(), selfCert)
		}
		return r.parseFromRequest(req, successHandler)
	}
}

func (r *tokensResource) RevokeToken(req *http.Request) (interface{}, error) {
	successHandler := func(token *jwt.Token) (interface{}, error) {
		sha256 := revocations.RawSha256FromData(token.Raw)
		expiresAt := time.Unix((int64)(token.Claims["exp"].(float64)), 0)
		return nil, r.store.AddRevocation(sha256, expiresAt)
	}
	return r.parseFromRequest(req, successHandler)
}

type SuccessHandler func(token *jwt.Token) (interface{}, error)

func (r *tokensResource) newExpirationTime() time.Time {
	return time.Now().Add(15 * time.Minute)
}

func (r *tokensResource) parseFromRequest(req *http.Request, successHandler SuccessHandler) (interface{}, error) {
	if token, err := jwt.ParseFromRequest(req, r.tokenHandler); err == nil {
		return successHandler(token)
	} else {
		r.logger.Error(err)
		return nil, Unauthorized()
	}
}

func (r *tokensResource) tokenHandler(token *jwt.Token) (interface{}, error) {
	r.logger.Debugf("Token: %s", *token)
	err := r.verifyRevocations(token)
	if err != nil {
		return nil, err
	} else {
		return r.verifyCertificate(token)
	}
}

func (r *tokensResource) verifyCertificate(token *jwt.Token) (interface{}, error) {
	x5t := token.Header["x5t"]
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

func (r *tokensResource) verifyRevocations(token *jwt.Token) error {
	revoked, err := r.store.IsRevoked(revocations.RawSha256FromData(token.Raw))
	if err != nil {
		return err
	}
	if revoked {
		return errors.New("Token has been revoked")
	}
	return nil
}
