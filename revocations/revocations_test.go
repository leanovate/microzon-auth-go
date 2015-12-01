package revocations

import (
	"crypto/rand"
	"github.com/leanovate/microzon-auth-go/logging"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
)

func TestRevokations(t *testing.T) {
	Convey("Given an empty revokations list", t, func() {
		revocations := NewRevocations(logging.NewSimpleLoggerNull())

		Convey("When revokation is added", func() {
			var hash RawSha256
			rand.Read(hash[:])

			revocations.AddRevocation(1, hash, time.Now().Add(10*time.Minute))

			So(revocations.ContainsHash(hash), ShouldBeTrue)
			_, ok := revocations.revocationsByVersion.Get(uint64(1))
			So(ok, ShouldBeTrue)
			So(revocations.CurrentVersion(), ShouldEqual, 1)

			Convey("When revokation list is queried", func() {
				revocationList := revocations.GetRevocationsSinceVersion(0, 200)

				So(revocationList.Version, ShouldEqual, 1)
				So(len(revocationList.Revocations), ShouldEqual, 1)
			})

			Convey("When revokations are cleaned up", func() {
				revocations.cleanup()

				So(revocations.ContainsHash(hash), ShouldBeTrue)
				_, ok := revocations.revocationsByVersion.Get(uint64(1))
				So(ok, ShouldBeTrue)
				So(revocations.CurrentVersion(), ShouldEqual, 1)
			})
		})
	})

	Convey("Given revokations list with expired entries", t, func() {
		revocations := NewRevocations(logging.NewSimpleLoggerNull())
		past := time.Now().Add(-10 * time.Minute)
		for i := 0; i < 100; i++ {
			var hash RawSha256
			rand.Read(hash[:])

			revocations.AddRevocation(uint64(i+1), hash, past.Add(time.Duration(i)*time.Second))
		}

		So(len(revocations.revocationHashes), ShouldEqual, 100)
		So(revocations.revocationsByVersion.Len(), ShouldEqual, 100)
		So(revocations.CurrentVersion(), ShouldEqual, 100)

		Convey("When revokation list is queried", func() {
			revocationList := revocations.GetRevocationsSinceVersion(50, 200)

			So(revocationList.Version, ShouldEqual, 100)
			So(revocationList.Revocations, ShouldHaveLength, 50)
		})

		Convey("When revokations are cleaned up", func() {
			revocations.cleanup()

			So(revocations.revocationHashes, ShouldHaveLength, 0)
			So(revocations.revocationsByVersion.Len(), ShouldEqual, 0)
			So(revocations.CurrentVersion(), ShouldEqual, 100)
		})

		Convey("When some non-expired revokations are added", func() {
			future := time.Now().Add(10 * time.Minute)
			for i := 0; i < 50; i++ {
				var hash RawSha256
				rand.Read(hash[:])

				revocations.AddRevocation(uint64(101+i), hash, future.Add(time.Duration(i)*time.Second))
			}

			So(revocations.revocationHashes, ShouldHaveLength, 150)
			So(revocations.revocationsByVersion.Len(), ShouldEqual, 150)
			So(revocations.CurrentVersion(), ShouldEqual, 150)

			Convey("When revokations are cleaned up", func() {
				revocations.cleanup()

				So(revocations.revocationHashes, ShouldHaveLength, 50)
				So(revocations.revocationsByVersion.Len(), ShouldEqual, 50)
				So(revocations.CurrentVersion(), ShouldEqual, 150)
			})
		})
	})
}
