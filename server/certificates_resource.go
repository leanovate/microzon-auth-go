package server

import (
	"net/http"

	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store"
	"github.com/untoldwind/routing"
)

type certificatesResource struct {
	store  store.Store
	logger logging.Logger
}

func CertificatesRoutes(store store.Store, parent logging.Logger) routing.Matcher {
	logger := parent.WithContext(map[string]interface{}{"resource": "certificates"})
	resource := &certificatesResource{
		store:  store,
		logger: logger,
	}
	return routing.PrefixSeq("/certificates",
		routing.EndSeq(
			routing.GETFunc(wrap(resource.logger, resource.QueryCertificates)),
			SendError(logger, MethodNotAllowed()),
		),
		routing.StringPart(
			func(x5t string) routing.Matcher {
				return routing.EndSeq(
					routing.GETFunc(wrap(resource.logger, resource.GetCertByThumbprint(x5t))),
					SendError(logger, MethodNotAllowed()),
				)
			},
		),
	)
}

func (r *certificatesResource) QueryCertificates(req *http.Request) (interface{}, error) {
	certs, err := r.store.AllCertificates()
	if err != nil {
		return nil, err
	}
	result := make([]*certificates.CertificateVO, 0, len(certs))
	for _, cert := range certs {
		result = append(result, certificates.NewCertificateVO(cert))
	}
	return result, nil
}

func (r *certificatesResource) GetCertByThumbprint(x5t string) func(req *http.Request) (interface{}, error) {
	return func(req *http.Request) (interface{}, error) {
		cert, err := r.store.CertificateByThumbprint(x5t)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			return nil, NotFound()
		}
		return certificates.NewCertificateVO(cert), nil
	}
}
