package server

import (
	"encoding/json"
	"github.com/leanovate/microzon-auth-go/certificates"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCertificatesResource(t *testing.T) {
	Convey("Given a certicates resource", t, func() {
		storeConfig := config.NewStoreConfig(logging.NewSimpleLoggerNull())
		store, err := memory_backend.NewMemoryStore(storeConfig, logging.NewSimpleLoggerNull())

		So(err, ShouldBeNil)

		selfCert, err := store.SelfCertificate()

		So(err, ShouldBeNil)

		routes := CertificatesRoutes(store, logging.NewSimpleLoggerNull())

		Convey("When all certificates are queried requested", func() {
			recorder := httptest.NewRecorder()
			request, _ := http.NewRequest("GET", "/v1/certificates", nil)
			match := routes("/certificates", recorder, request)

			So(match, ShouldBeTrue)
			So(recorder.Code, ShouldEqual, 200)
			So(recorder.Header().Get("content-type"), ShouldEqual, "application/json")
			var data []*certificates.CertificateVO
			err := json.NewDecoder(recorder.Body).Decode(&data)
			So(err, ShouldBeNil)
			So(data, ShouldHaveLength, 1)
			So(data[0].X5t, ShouldEqual, selfCert.Thumbprint)
		})

		Convey("When self certifcate is queried", func() {
			thumbprint := selfCert.Thumbprint
			recorder := httptest.NewRecorder()
			request, _ := http.NewRequest("GET", "/v1/certificates/"+thumbprint, nil)
			match := routes("/certificates/"+thumbprint, recorder, request)

			So(match, ShouldBeTrue)
			So(recorder.Code, ShouldEqual, 200)
			So(recorder.Header().Get("content-type"), ShouldEqual, "application/json")
			var data certificates.CertificateVO
			err := json.NewDecoder(recorder.Body).Decode(&data)
			So(err, ShouldBeNil)
			So(data.X5t, ShouldEqual, selfCert.Thumbprint)
		})
	})
}
