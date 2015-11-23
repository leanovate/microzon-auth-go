package server

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/leanovate/microzon-auth-go/logging"
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
				routing.MethodNotAllowed,
			),
		),
	)
}

func (r *tokensResource) CreateToken(req *http.Request) (interface{}, error) {
	selfCert, err := r.store.SelfCertificate()
	if err != nil {
		return nil, err
	}
	return tokens.NewTokenInfo("realm", "user", time.Now().Add(15*time.Minute), selfCert)
}

func (r *tokensResource) VerifyToken(req *http.Request) (interface{}, error) {
	handler := func(token *jwt.Token) (interface{}, error) {
		if time.Unix(token.Claims["exp"].(int64), 0).Before(time.Now()) {
			return nil, errors.New("Token is expired")
		}
		if r, err := r.store.ListRevokations(0); err == nil {
			for _, rev := range r.Revokations {
				if rev.Sha256 == tokens.ToSha256(token.Raw) {
					return nil, errors.New("Token has been revoked")
				}
			}
		}
		if cert, err := r.store.CertificateByThumbprint(token.Header["x5t"].(string)); err != nil {
			return nil, err
		} else {
			return cert.PublicKey, err
		}
	}
	if token, err := jwt.ParseFromRequest(req, handler); err == nil {
		return tokens.CopyFromToken(token)
	} else {
		return nil, err
	}

}
