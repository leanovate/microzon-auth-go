package revocations

import (
	"sort"
	"sync"
	"time"
)

type timeWheelEntry struct {
	expiresAt int64
	version   uint64
}

type timeWheelHeap []timeWheelEntry

func (h timeWheelHeap) Len() int           { return len(h) }
func (h timeWheelHeap) Less(i, j int) bool { return h[i].expiresAt < h[j].expiresAt }
func (h timeWheelHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

type timeWheelNode struct {
	lock sync.Mutex
	heap timeWheelHeap
}

func (t *timeWheelNode) addEntry(expiresAt int64, version uint64) {
	t.lock.Lock()
	defer t.lock.Unlock()

	t.heap = append(t.heap, timeWheelEntry{expiresAt: expiresAt, version: version})
	sort.Sort(t.heap)
}

func (t *timeWheelNode) getExpiredVersions(now int64) []uint64 {
	t.lock.Lock()
	defer t.lock.Unlock()

	var index int = 0
	for index < len(t.heap) && t.heap[index].expiresAt < now {
		index++
	}
	if index == 0 {
		return make([]uint64, 0)
	}
	result := make([]uint64, 0, index)
	for i := 0; i < index; i++ {
		result = append(result, t.heap[i].version)
	}
	t.heap = t.heap[:copy(t.heap, t.heap[index:])]

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

	if nowUnix <= t.lastCleanup || nowUnix-t.lastCleanup >= int64(t.size) {
		for i := uint32(0); i < t.size; i++ {
			result = append(result, t.wheel[i].getExpiredVersions(nowUnix)...)
		}
	} else {
		from := t.calculateIndex(t.lastCleanup)
		to := t.calculateIndex(nowUnix)

		for i := from; (i % t.size) < to; i++ {
			result = append(result, t.wheel[i%t.size].getExpiredVersions(nowUnix)...)
		}
	}
	t.lastCleanup = nowUnix

	return result
}
