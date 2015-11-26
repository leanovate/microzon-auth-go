package revocations

import (
	"github.com/leanovate/microzon-auth-go/logging"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
	"crypto/rand"
)

func TestRevokations(t *testing.T) {
	Convey("Given an empty revokations list", t, func() {
		revocations := NewRevokations(logging.NewSimpleLoggerNull())

		Convey("When revokation is added", func() {
			var hash RawSha256
			rand.Read(hash[:])
			revocation := NewRevocation(1, hash, time.Now().Add(10*time.Minute))

			revocations.AddRevokation(revocation)

			So(revocations.ContainsHash(hash), ShouldBeTrue)
			So(revocations.revocationsByVersion[1], ShouldNotBeNil)
			So(revocations.minVersion, ShouldEqual, 0)
			So(revocations.maxVersion, ShouldEqual, 1)

			Convey("When revokation list is queried", func() {
				revocationList := revocations.GetRevocationsSinceVersion(0)

				So(revocationList.Version, ShouldEqual, 1)
				So(len(revocationList.Revocations), ShouldEqual, 1)
			})

			Convey("When revokations are cleaned up", func() {
				revocations.cleanup()

				So(revocations.ContainsHash(hash), ShouldBeTrue)
				So(revocations.revocationsByVersion[1], ShouldNotBeNil)
				So(revocations.minVersion, ShouldEqual, 0)
				So(revocations.maxVersion, ShouldEqual, 1)
			})
		})
	})

	Convey("Given revokations list with expired entries", t, func() {
		revocations := NewRevokations(logging.NewSimpleLoggerNull())
		past := time.Now().Add(-10 * time.Minute)
		for i := 0; i < 100; i++ {
			var hash RawSha256
			rand.Read(hash[:])
			revocation := NewRevocation(uint64(i + 1), hash, past.Add(time.Duration(i)*time.Second))

			revocations.AddRevokation(revocation)
		}

		So(len(revocations.revocationsByHash), ShouldEqual, 100)
		So(len(revocations.revocationsByVersion), ShouldEqual, 100)
		So(revocations.maxVersion, ShouldEqual, 100)
		So(revocations.minVersion, ShouldEqual, 0)

		Convey("When revokation list is queried", func() {
			revocationList := revocations.GetRevocationsSinceVersion(50)

			So(revocationList.Version, ShouldEqual, 100)
			So(len(revocationList.Revocations), ShouldEqual, 50)
		})

		Convey("When revokations are cleaned up", func() {
			revocations.cleanup()

			So(len(revocations.revocationsByHash), ShouldEqual, 0)
			So(len(revocations.revocationsByVersion), ShouldEqual, 0)
			So(revocations.maxVersion, ShouldEqual, 100)
			So(revocations.minVersion, ShouldEqual, 100)
		})

		Convey("When some non-expired revokations are added", func() {
			future := time.Now().Add(10 * time.Minute)
			for i := 0; i < 50; i++ {
				var hash RawSha256
				rand.Read(hash[:])
				revocation := NewRevocation(uint64(101 + i), hash, future.Add(time.Duration(i)*time.Second))

				revocations.AddRevokation(revocation)
			}

			So(len(revocations.revocationsByHash), ShouldEqual, 150)
			So(len(revocations.revocationsByVersion), ShouldEqual, 150)
			So(revocations.maxVersion, ShouldEqual, 150)
			So(revocations.minVersion, ShouldEqual, 0)

			Convey("When revokations are cleaned up", func() {
				revocations.cleanup()

				So(len(revocations.revocationsByHash), ShouldEqual, 50)
				So(len(revocations.revocationsByVersion), ShouldEqual, 50)
				So(revocations.maxVersion, ShouldEqual, 150)
				So(revocations.minVersion, ShouldEqual, 101)
			})
		})
	})
}
