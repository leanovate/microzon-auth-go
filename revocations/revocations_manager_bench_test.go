package revocations

import (
	"fmt"
	"github.com/leanovate/microzon-auth-go/common"
	"github.com/leanovate/microzon-auth-go/config"
	"github.com/leanovate/microzon-auth-go/logging"
	"github.com/leanovate/microzon-auth-go/store/memory_backend"
	"testing"
	"time"
)

func BenchmarkRevocationsManagerFill(b *testing.B) {
	storeConfig := config.NewStoreConfig(logging.NewSimpleLoggerNull())
	store, _ := memory_backend.NewMemoryStore(storeConfig, logging.NewSimpleLoggerNull())

	revocations, _ := NewRevocationsManager(store, logging.NewSimpleLoggerNull())

	now := time.Now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.AddRevocation(common.RawSha256FromData(fmt.Sprintf("data%d", i)), now)
		if !revocations.IsRevoked(common.RawSha256FromData(fmt.Sprintf("data%d", i))) {
			b.Fail()
		}
	}
}
