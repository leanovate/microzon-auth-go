package revocations

import (
	"container/heap"
	"sync"
	"time"
)

type timeWheelHeap []*RevocationVO

func (h timeWheelHeap) Len() int           { return len(h) }
func (h timeWheelHeap) Less(i, j int) bool { return h[i].ExpiresAt < h[j].ExpiresAt }
func (h timeWheelHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *timeWheelHeap) Push(x interface{}) {
	*h = append(*h, x.(*RevocationVO))
}

func (h *timeWheelHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = nil
	if 2*n < cap(old) {
		*h = append(timeWheelHeap(nil), old[0:n-1]...)
	} else {
		*h = old[0 : n-1]
	}
	return x
}

type timeWheelNode struct {
	lock sync.Mutex
	heap timeWheelHeap
}

func (t *timeWheelNode) addEntry(revocation *RevocationVO) {
	t.lock.Lock()
	defer t.lock.Unlock()

	heap.Push(&t.heap, revocation)
}

func (t *timeWheelNode) getExpiredRevocations(now int64) []*RevocationVO {
	t.lock.Lock()
	defer t.lock.Unlock()

	result := make([]*RevocationVO, 0)
	for len(t.heap) > 0 && t.heap[0].ExpiresAt < now {
		result = append(result, heap.Pop(&t.heap).(*RevocationVO))
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

func (t *timeWheel) AddEntry(revocation *RevocationVO) {
	index := t.calculateIndex(revocation.ExpiresAt)
	t.wheel[index].addEntry(revocation)
}

func (t *timeWheel) getExpiredRevocations(now time.Time) []*RevocationVO {
	nowUnix := now.Unix()
	result := make([]*RevocationVO, 0)

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
		result = append(result, t.wheel[i%t.size].getExpiredRevocations(nowUnix)...)
	}
	t.lastCleanup = nowUnix

	return result
}
