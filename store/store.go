package store

import (
	"github.com/leanovate/microzon-auth-go/certificates"
)

type Store interface {
	SelfCerificate() (*certificates.CertWithKey, error)
	AllCertificates() ([]*certificates.CertificateVO, error)
	CertificateBySKI(ski string) (*certificates.CertificateVO, error)
}
