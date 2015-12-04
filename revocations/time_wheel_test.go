package revocations

import (
	"container/heap"
	"github.com/leanovate/microzon-auth-go/common"
	. "github.com/smartystreets/goconvey/convey"
	"math/rand"
	"testing"
	"time"
)

func TestTimeWheel(t *testing.T) {
	Convey("Given a time wheel node", t, func() {
		now := time.Now()
		node := timeWheelNode{}

		Convey("When expirations are added", func() {
			start := now.Add(1 * time.Minute)
			for i := 0; i < 1000; i++ {
				node.addEntry(NewRevokationVO(uint64(i), common.RawSha256FromData("data"), start.Add(time.Duration(i)*time.Minute)))
			}

			So(node.heap, ShouldHaveLength, 1000)
			So(node.getExpiredVersions(now.Unix()), ShouldHaveLength, 0)

			expired := node.getExpiredVersions(now.Add(300 * time.Minute).Add(1 * time.Second).Unix())

			So(expired, ShouldHaveLength, 300)
			expected := make([]uint64, 300)
			for i := 0; i < 300; i++ {
				expected[i] = (uint64)(i)
			}
			So(expired, ShouldResemble, expected)

			So(node.heap, ShouldHaveLength, 700)
			expectedRemains := make([]uint64, 700)
			for i := 0; i < 700; i++ {
				expectedRemains[i] = (uint64)(i + 300)
			}
			actualRemains := node.getExpiredVersions(now.Add(24 * time.Hour).Unix())
			So(actualRemains, ShouldResemble, expectedRemains)
		})

		Convey("When expirations are randomly address", func() {
			start := now.Add(1 * time.Minute)
			for i := 0; i < 1000; i++ {
				diff := rand.Intn(20000)
				node.addEntry(NewRevokationVO(uint64(i), common.RawSha256FromData("data"), start.Add(time.Duration(diff)*time.Second)))
			}

			So(node.heap, ShouldHaveLength, 1000)
			So(node.getExpiredVersions(now.Unix()), ShouldHaveLength, 0)

			last := heap.Pop(&node.heap).(*RevocationVO)
			var i int
			for i = 1; i < 1000; i++ {
				current := heap.Pop(&node.heap).(*RevocationVO)
				if current.ExpiresAt < last.ExpiresAt {
					break
				}
				last = current
			}
			So(i, ShouldEqual, 1000)
		})
	})

	Convey("Given a time wheel for 10 minutes", t, func() {
		now := time.Now()
		timeWheel := newTimeWheel(600)

		Convey("When expirations are added", func() {
			start := now.Add(1 * time.Minute)
			for i := 0; i < 10000; i++ {
				timeWheel.AddEntry(NewRevokationVO(uint64(i), common.RawSha256FromData("data"), start.Add(time.Duration(i+1)*time.Second)))
			}

			So(timeWheel.GetExpiredVersions(now), ShouldHaveLength, 0)

			expired := timeWheel.GetExpiredVersions(start.Add(3001 * time.Second))

			So(expired, ShouldHaveLength, 3000)
			versions := make(map[uint64]bool, 0)
			for _, version := range expired {
				if version < 3000 {
					versions[version] = true
				}
			}
			So(versions, ShouldHaveLength, 3000)

			expired = timeWheel.GetExpiredVersions(start.Add(3201 * time.Second))

			So(expired, ShouldHaveLength, 200)
			versions = make(map[uint64]bool, 0)
			for _, version := range expired {
				if version >= 3000 && version < 3200 {
					versions[version] = true
				}
			}
			So(versions, ShouldHaveLength, 200)
		})
	})
}
