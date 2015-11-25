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
		r.logger.Debugf("Token: %s", *token)
		err := r.verifyRevokations(token)
		if err != nil {
			return nil, err
		} else {
			return r.verifyCertificate(token)
		}
	}
	if token, err := jwt.ParseFromRequest(req, handler); err == nil {
		return tokens.CopyFromToken(token)
	} else {
		r.logger.Error(err)
		return nil, NotFound()
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

func (r *tokensResource) verifyRevokations(token *jwt.Token) error {
	//TODO: choose right version for revocation
	if revs, err := r.store.ListRevocations(0); err == nil {
		for _, rev := range revs.Revocations {
			if rev.Sha256 == tokens.ToSha256(token.Raw) {
				return errors.New("Token has been revoked")
			}
		}
		return nil
	} else {
		return err
	}
}
