package revocations
import (
	"testing"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
	"time"
	"github.com/leanovate/microzon-auth-go/common"
	"fmt"
)

func BenchmarkRevocationsManagerFill(b *testing.B) {
	storeConfig := config.NewStoreConfig(logging.NewSimpleLoggerNull())
	store, _ := memory_backend.NewMemoryStore(storeConfig, logging.NewSimpleLoggerNull())

	revocations, _ := NewRevocationsManager(store, logging.NewSimpleLoggerNull())

	now := time.Now()
	hashes := make([]common.RawSha256, b.N)
	for i := 0; i < b.N; i++ {
		hashes[i] = common.RawSha256FromData(fmt.Sprintf("data%d", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		revocations.AddRevocation(hashes[i], now)
		if !revocations.IsRevoked(hashes[i]) {
			b.Fail()
		}
	}
}