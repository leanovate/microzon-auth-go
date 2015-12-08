package revocations

import (
	"github.com/leanovate/microzon-auth-go/common"
	"math/rand"
	"testing"
	"time"
)

func BenchmarkVersionWheelFill17(b *testing.B) {
	versionWheel := newVersionWheel(17)

	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		versionWheel.addRevocation(NewRevokationVO(uint64(i), common.RawSha256FromData("data"), now))
	}
}

func BenchmarkVersionWheelGet17(b *testing.B) {
	versionWheel := newVersionWheel(17)

	now := time.Now()
	versions := make([]uint64, b.N)
	for i := 0; i < b.N; i++ {
		versionWheel.addRevocation(NewRevokationVO(uint64(i), common.RawSha256FromData("data"), now))
		versions[i] = uint64(rand.Int63n(int64(b.N)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if versionWheel.getVersion(versions[i]) == nil {
			b.Fail()
		}
	}
}

func BenchmarkVersionWheelRemove17(b *testing.B) {
	versionWheel := newVersionWheel(17)

	now := time.Now()
	versions := make([]uint64, b.N)
	for i := 0; i < b.N; i++ {
		versionWheel.addRevocation(NewRevokationVO(uint64(i), common.RawSha256FromData("data"), now))
		versions[i] = uint64(rand.Int63n(int64(b.N)))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		versionWheel.removeVersion(versions[i])
	}
}

func BenchmarkVersionWheelFill18(b *testing.B) {
	versionWheel := newVersionWheel(18)

	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		versionWheel.addRevocation(NewRevokationVO(uint64(i), common.RawSha256FromData("data"), now))
	}
}
