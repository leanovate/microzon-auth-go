package revocations

import (
	"sync"
	"time"
	"container/heap"
)

type timeWheelEntry struct {
	expiresAt int64
	version   uint64
}

type timeWheelHeap []timeWheelEntry

func (h timeWheelHeap) Len() int           { return len(h) }
func (h timeWheelHeap) Less(i, j int) bool { return h[i].expiresAt < h[j].expiresAt }
func (h timeWheelHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *timeWheelHeap) Push(x interface{}) {
	*h = append(*h, x.(timeWheelEntry))
}

func (h *timeWheelHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

type timeWheelNode struct {
	lock sync.Mutex
	heap timeWheelHeap
}

func (t *timeWheelNode) addEntry(expiresAt int64, version uint64) {
	t.lock.Lock()
	defer t.lock.Unlock()

	heap.Push(&t.heap, timeWheelEntry{expiresAt: expiresAt, version: version})
}

func (t *timeWheelNode) getExpiredVersions(now int64) []uint64 {
	t.lock.Lock()
	defer t.lock.Unlock()

	result := make([]uint64, 0)
	for len(t.heap) >0 && t.heap[0].expiresAt < now {
		result = append(result, heap.Pop(&t.heap).(timeWheelEntry).version)
	}

	return result
}

type timeWheel struct {
	size        uint32
	lastCleanup int64
	wheel       []timeWheelNode
}

func newTimeWheel(size uint32) *timeWheel {
	return &timeWheel{
		size:        size,
		lastCleanup: time.Now().Unix(),
		wheel:       make([]timeWheelNode, size),
	}
}

func (t *timeWheel) calculateIndex(time int64) uint32 {
	return uint32(time % int64(t.size))
}

func (t *timeWheel) AddEntry(expiresAt time.Time, version uint64) {
	expiresAtUnix := expiresAt.Unix()
	index := t.calculateIndex(expiresAtUnix)
	t.wheel[index].addEntry(expiresAtUnix, version)
}

func (t *timeWheel) GetExpiredVersions(now time.Time) []uint64 {
	nowUnix := now.Unix()
	result := make([]uint64, 0)

	var to, from uint32
	if nowUnix <= t.lastCleanup || nowUnix-t.lastCleanup >= int64(t.size) {
		from = 0
		to = t.size
	} else {
		from = t.calculateIndex(t.lastCleanup)
		to = t.calculateIndex(nowUnix)
		if to < from {
			to += t.size
		}
	}
	for i := from; i < to; i++ {
		result = append(result, t.wheel[i%t.size].getExpiredVersions(nowUnix)...)
	}
	t.lastCleanup = nowUnix

	return result
}
