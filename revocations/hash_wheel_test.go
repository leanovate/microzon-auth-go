package revocations

import (
	"fmt"
	"github.com/leanovate/microzon-auth-go/common"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
)

func TestHashWheel(t *testing.T) {
	Convey("Geven a version wheel node", t, func() {
		var node hashWheelNode

		So(node, ShouldBeNil)

		Convey("When revocations are added", func() {
			now := time.Now()
			for i := 0; i < 1000; i++ {
				node.addRevocation(NewRevokationVO(uint64(i), common.RawSha256FromData(fmt.Sprintf("data%d", i)), now.Add(time.Duration(i+1)*time.Second)))
			}

			So(node, ShouldHaveLength, 1000)

			Convey("When all revocations are removed", func() {
				for i := 0; i < 1000; i++ {
					node.removeHash(common.RawSha256FromData(fmt.Sprintf("data%d", i)))
				}

				So(node, ShouldHaveLength, 0)
				So(cap(node), ShouldEqual, 1)
			})

			Convey("When first half is removed", func() {
				for i := 0; i < 600; i++ {
					node.removeHash(common.RawSha256FromData(fmt.Sprintf("data%d", i)))
				}

				So(node, ShouldHaveLength, 400)
				So(cap(node), ShouldBeLessThan, 600)
			})
		})
	})
}
