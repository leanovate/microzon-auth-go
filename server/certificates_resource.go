package server

import (
	"net/http"

	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/untoldwind/routing"
)

type certificatesResource struct {
	store  *store.Store
	logger logging.Logger
}

func (s *Server) CertificatesRoutes() routing.Matcher {
	resource := &certificatesResource{
		store:  s.store,
		logger: s.logger.WithContext(map[string]interface{}{"resource": "certificates"}),
	}
	return routing.PrefixSeq("/certificates",
		routing.EndSeq(
			routing.GETFunc(wrap(resource.logger, resource.QueryCertificates)),
			routing.MethodNotAllowed,
		),
		routing.StringPart(
			func(ski string) routing.Matcher {
				return routing.EndSeq(
					routing.GETFunc(wrap(resource.logger, resource.GetCertBySki(ski))),
				)
			},
		),
	)
}

func (r *certificatesResource) QueryCertificates(req *http.Request) (interface{}, error) {
	result := []*certificates.CertificateVO{}

	for _, certificate := range r.store.Certificates {
		result = append(result, certificates.NewCertificateVO(certificate))
	}

	return result, nil
}

func (r *certificatesResource) GetCertBySki(ski string) func(req *http.Request) (interface{}, error) {
	return func(req *http.Request) (interface{}, error) {
		if cert, ok := r.store.Certificates[ski]; ok {
			return cert, nil
		}
		return nil, NotFound()
	}
}
