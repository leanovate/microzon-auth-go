package certificates

import (
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
)

func TestCertWithKey(t *testing.T) {
	Convey("Given new certificate with key", t, func() {
		certWithKey, err := NewCertWithKey("some subject", 10*time.Minute, 10*time.Minute)

		So(err, ShouldBeNil)
		So(certWithKey.Name, ShouldEqual, "some subject")
		cert := certWithKey.Certificate
		So(cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature), ShouldBeNil)
		So(cert.NotBefore.Unix(), ShouldBeLessThan, time.Now().Unix())
		So(cert.NotAfter.Unix(), ShouldBeGreaterThan, time.Now().Unix())
	})
}
