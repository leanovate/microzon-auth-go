package revocations

import (
	"github.com/leanovate/microzon-auth-go/common"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
)

func TestVersionWheel(t *testing.T) {
	Convey("Geven a version wheel node", t, func() {
		var node versionWheelNode

		So(node, ShouldBeNil)

		Convey("When revocations are added", func() {
			now := time.Now()
			for i := 0; i < 1000; i++ {
				node.addRevocation(NewRevokationVO(uint64(i), common.RawSha256FromData("data"), now.Add(time.Duration(i+1)*time.Second)))
			}

			So(node, ShouldHaveLength, 1000)

			Convey("When all revocations are removed", func() {
				for i := 0; i < 1000; i++ {
					node.removeVersion(uint64(i))
				}

				So(node, ShouldHaveLength, 0)
				So(cap(node), ShouldEqual, 1)
			})

			Convey("When first half is removed", func() {
				for i := 0; i < 600; i++ {
					node.removeVersion(uint64(i))
				}

				So(node, ShouldHaveLength, 400)
				So(cap(node), ShouldBeLessThan, 600)

				var version uint64
				for version = 600; version < 1000-1; version++ {
					next := node.nextCandidate(version)

					if next == nil || next.Version != version+1 {
						break
					}
				}
				So(version, ShouldEqual, 1000-1)
				So(node.nextCandidate(999), ShouldBeNil)
			})

			Convey("When odds are remove", func() {
				for i := 1; i < 1000; i += 2 {
					node.removeVersion(uint64(i))
				}

				So(node, ShouldHaveLength, 500)
				So(cap(node), ShouldBeLessThan, 600)

				var version uint64
				for version = 0; version < 1000-2; version += 2 {
					next := node.nextCandidate(version)

					if next == nil || next.Version != version+2 {
						break
					}
				}
				So(version, ShouldEqual, 1000-2)
				So(node.nextCandidate(999), ShouldBeNil)
			})
		})
	})

	Convey("Given an empty version wheel", t, func() {
		versionWheel := newVersionWheel(8)

		So(versionWheel.size, ShouldEqual, 0x100)
		So(versionWheel.mask, ShouldEqual, 0xff)
		So(versionWheel.count(), ShouldEqual, 0)
		So(versionWheel.getVersion(uint64(5000)), ShouldBeNil)

		Convey("When revocations are added", func() {
			now := time.Now()
			for i := 0; i < 10000; i++ {
				versionWheel.addRevocation(NewRevokationVO(uint64(i), common.RawSha256FromData("data"), now.Add(time.Duration(i+1)*time.Second)))
			}

			So(versionWheel.count(), ShouldEqual, 10000)
			So(versionWheel.getVersion(uint64(5000)), ShouldNotBeNil)

			Convey("When versions are removed", func() {
				for i := 0; i < 10000; i++ {
					versionWheel.removeVersion(uint64(i))
				}

				So(versionWheel.count(), ShouldEqual, 0)
				So(versionWheel.getVersion(uint64(5000)), ShouldBeNil)
			})
		})
	})
}
