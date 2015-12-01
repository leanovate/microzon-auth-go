package server

import (
	"encoding/json"
	"github.com/golang/mock/gomock"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/revocations"
	"github.com/leanovate/microzon-auth-go/store"
	. "github.com/smartystreets/goconvey/convey"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRevocationsResource(t *testing.T) {
	Convey("Given a revocations resource", t, func() {
		ctrl := gomock.NewController(t)
		store := store.NewMockStore(ctrl)
		routes := RevocationsRoutes(store, logging.NewSimpleLoggerNull())

		Convey("When all recocations are queried", func() {
			expected := revocations.NewRevokationVO(revocations.RawSha256FromData("somedata"), time.Now())
			expectedList := revocations.NewRevocationListVO(10, []*revocations.RevocationVO{expected})
			store.EXPECT().ListRevocations(uint64(0), 200).Return(expectedList, nil)
			recorder := httptest.NewRecorder()
			request, _ := http.NewRequest("GET", "/v1/revocations", nil)
			match := routes("/revocations", recorder, request)

			So(match, ShouldBeTrue)
			var actual revocations.RevocationListVO
			err := json.NewDecoder(recorder.Body).Decode(&actual)
			So(err, ShouldBeNil)
			So(actual.Version, ShouldEqual, expectedList.Version)
			So(actual.Revocations, ShouldResemble, expectedList.Revocations)
		})
	})
}
