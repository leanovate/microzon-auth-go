package certificates

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestCertWithKey(t *testing.T) {
	Convey("Given new certificate with key", t, func() {
		certWithKey, err := NewCertWithKey("some subject")

		So(err, ShouldBeNil)
		So(certWithKey.Name, ShouldEqual, "some subject")
		cert := certWithKey.Certificate
		So(cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature), ShouldBeNil)
	})
}
