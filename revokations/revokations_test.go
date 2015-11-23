package revokations

import (
	"fmt"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
)

func TestRevokations(t *testing.T) {
	Convey("Given an empty revokations list", t, func() {
		revokations := NewRevokations()

		Convey("When revokation is added", func() {
			revokation := NewRevokationVO(1, "abcd", time.Now().Add(10*time.Minute))

			revokations.AddRevokation(revokation)

			So(revokations.ContainsHash("abcd"), ShouldBeTrue)
			So(revokations.RevokationsByVersion[1], ShouldNotBeNil)
			So(revokations.minVersion, ShouldEqual, 0)
			So(revokations.maxVersion, ShouldEqual, 1)

			Convey("When revokation list is queried", func() {
revokationList :=				revokations.GetRevokationsSinceVersion(0)

				So(revokationList.Version, ShouldEqual, 1)
				So(len(revokationList.Revokations), ShouldEqual, 1)
			})

			Convey("When revokations are cleaned up", func() {
				revokations.cleanup()

				So(revokations.ContainsHash("abcd"), ShouldBeTrue)
				So(revokations.RevokationsByVersion[1], ShouldNotBeNil)
				So(revokations.minVersion, ShouldEqual, 0)
				So(revokations.maxVersion, ShouldEqual, 1)
			})
		})
	})

	Convey("Given revokations list with expired entries", t, func() {
		revokations := NewRevokations()
		past := time.Now().Add(-10 * time.Minute)
		for i := 0; i < 100; i++ {
			revokation := NewRevokationVO(uint64(i+1), fmt.Sprintf("abcd%d", i), past.Add(time.Duration(i)*time.Second))

			revokations.AddRevokation(revokation)
		}

		So(len(revokations.revokationsByHash), ShouldEqual, 100)
		So(len(revokations.RevokationsByVersion), ShouldEqual, 100)
		So(revokations.maxVersion, ShouldEqual, 100)
		So(revokations.minVersion, ShouldEqual, 0)

		Convey("When revokation list is queried", func() {
			revokationList :=				revokations.GetRevokationsSinceVersion(50)

			So(revokationList.Version, ShouldEqual, 100)
			So(len(revokationList.Revokations), ShouldEqual, 50)
		})

		Convey("When revokations are cleaned up", func() {
			revokations.cleanup()

			So(len(revokations.revokationsByHash), ShouldEqual, 0)
			So(len(revokations.RevokationsByVersion), ShouldEqual, 0)
			So(revokations.maxVersion, ShouldEqual, 100)
			So(revokations.minVersion, ShouldEqual, 100)
		})

		Convey("When some non-expired revokations are added", func() {
			future := time.Now().Add(10 * time.Minute)
			for i := 0; i < 50; i++ {
				revokation := NewRevokationVO(uint64(i+101), fmt.Sprintf("dcba%d", i), future.Add(time.Duration(i)*time.Second))

				revokations.AddRevokation(revokation)
			}

			So(len(revokations.revokationsByHash), ShouldEqual, 150)
			So(len(revokations.RevokationsByVersion), ShouldEqual, 150)
			So(revokations.maxVersion, ShouldEqual, 150)
			So(revokations.minVersion, ShouldEqual, 0)

			Convey("When revokations are cleaned up", func() {
				revokations.cleanup()

				So(len(revokations.revokationsByHash), ShouldEqual, 50)
				So(len(revokations.RevokationsByVersion), ShouldEqual, 50)
				So(revokations.maxVersion, ShouldEqual, 150)
				So(revokations.minVersion, ShouldEqual, 101)
			})
		})
	})
}
