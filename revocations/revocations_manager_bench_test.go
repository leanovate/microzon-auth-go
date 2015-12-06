package revocations
import (
	"testing"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
	"time"
	"github.com/leanovate/microzon-auth-go/common"
)

func BenchmarkRevocationsManagerFill(b *testing.B) {
	storeConfig := config.NewStoreConfig(logging.NewSimpleLoggerNull())
	store, _ := memory_backend.NewMemoryStore(storeConfig, logging.NewSimpleLoggerNull())

	revocations, _ := NewRevocationsManager(store, logging.NewSimpleLoggerNull())

	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		revocations.AddRevocation(common.RawSha256FromData("data"), now)
	}
}