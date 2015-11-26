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
	if token, err := jwt.ParseFromRequest(req, r.tokenHandler); err == nil {
		return tokens.CopyFromToken(token)
	} else {
		r.logger.Error(err)
		return nil, Unauthorized()
	}
}

func (r *tokensResource) RevokeToken(req *http.Request) (interface{}, error) {
	if token, err := jwt.ParseFromRequest(req, r.tokenHandler); err == nil {
		sha256 := revocations.RawSha256FromData(token.Raw)
		expiresAt := time.Unix((int64)(token.Claims["exp"].(float64)), 0)
		return nil, r.store.AddRevocation(sha256, expiresAt)
	} else {
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
