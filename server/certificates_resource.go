package server

import (
	"net/http"

	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/untoldwind/routing"
)

type certificatesResource struct {
	certificateManager *certificates.CertificateValidator
	logger             logging.Logger
}

func CertificatesRoutes(certificateManager *certificates.CertificateValidator, parent logging.Logger) routing.Matcher {
	logger := parent.WithContext(map[string]interface{}{"resource": "certificates"})
	resource := &certificatesResource{
		certificateManager: certificateManager,
		logger:             logger,
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
	certs, err := r.certificateManager.ListAllCertificates()
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
		cert, err := r.certificateManager.FindCertificate(x5t)
		if err != nil {
			return nil, err
		}
		if cert == nil {
			return nil, NotFound()
		}
		return certificates.NewCertificateVO(cert), nil
	}
}
