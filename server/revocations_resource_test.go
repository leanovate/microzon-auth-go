package server

import (
	"encoding/json"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRevocationsResource(t *testing.T) {
	Convey("Given a revocations resource", t, func() {
		storeConfig := config.NewStoreConfig(logging.NewSimpleLoggerNull())
		store, err := memory_backend.NewMemoryStore(storeConfig, logging.NewSimpleLoggerNull())

		So(err, ShouldBeNil)

		revocationsManager, err := revocations.NewRevocationsManager(store, logging.NewSimpleLoggerNull())

		So(err, ShouldBeNil)

		routes := RevocationsRoutes(revocationsManager, logging.NewSimpleLoggerNull())

		Convey("When all recocations are queried", func() {
			recorder := httptest.NewRecorder()
			request, _ := http.NewRequest("GET", "/v1/revocations", nil)
			match := routes("/revocations", recorder, request)

			So(match, ShouldBeTrue)
			var actual revocations.RevocationListVO
			err := json.NewDecoder(recorder.Body).Decode(&actual)
			So(err, ShouldBeNil)
			So(actual.LastVersion, ShouldEqual, 0)
			So(actual.Revocations, ShouldBeEmpty)
		})
	})
}
