package server

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/leanovate/microzon-auth-go/tokens"
	"github.com/untoldwind/routing"
	"net/http"
	"time"
)

type tokensResource struct {
	store        store.Store
	tokenManager *tokens.TokenManager
	logger       logging.Logger
}

func (s *Server) TokensResource() routing.Matcher {
	resource := &tokensResource{
		store:        s.store,
		tokenManager: s.tokenManager,
		logger:       s.logger.WithContext(map[string]interface{}{"resource": "tokens"}),
	}
	return routing.PrefixSeq("/tokens",
		routing.EndSeq(
			routing.POSTFunc(wrapCreate(resource.logger, resource.CreateToken)),
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

func (r *tokensResource) CreateToken(req *http.Request) (interface{}, string, error) {
	token, err := r.tokenManager.CreateToken("realm", "user")
	if err != nil {
		return nil, "", err
	}
	return token, "/tokens/myself", nil
}

func (r *tokensResource) VerifyToken(req *http.Request) (interface{}, error) {
	return r.parseFromRequest(req, tokens.CopyFromToken)
}

func (r *tokensResource) RefreshToken(req *http.Request) (interface{}, error) {
	return r.parseFromRequest(req, r.tokenManager.RefreshToken)
}

func (r *tokensResource) RevokeToken(req *http.Request) (interface{}, error) {
	return r.parseFromRequest(req, r.tokenManager.RevokeToken)
}

type SuccessHandler func(token *jwt.Token) (interface{}, error)

func (r *tokensResource) newExpirationTime() time.Time {
	return time.Now().Add(15 * time.Minute)
}

func (r *tokensResource) parseFromRequest(req *http.Request, successHandler SuccessHandler) (interface{}, error) {
	if token, err := jwt.ParseFromRequest(req, r.tokenManager.TokenHandler); err == nil {
		return successHandler(token)
	} else {
		r.logger.Error(err)
		return nil, Unauthorized()
	}
}
