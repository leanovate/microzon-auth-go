package revokations

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"sync"
	"time"
)

type ObserverGroup struct {
	logger    logging.Logger
	lock      sync.Mutex
	observers []chan struct{}
}

func NewObserverGroup(logger logging.Logger) *ObserverGroup {
	return &ObserverGroup{
		logger: logger.WithContext(map[string]interface{}{"package": "revokations"}),
	}
}
func (g *ObserverGroup) Notify() {
	g.logger.Debug("[ObserverGroup.Notify] waiting for lock ...")
	g.lock.Lock()
	defer g.lock.Unlock()
	g.logger.Debug("[ObserverGroup.Notify] got lock ...")

	for _, observer := range g.observers {
		select {
		case observer <- struct{}{}:
		default:
		}
	}
	g.observers = g.observers[:0]
	g.logger.Debug("[ObserverGroup.Notify] notified all ...")
}

func (g *ObserverGroup) AttachObserver(observer chan struct{}) {
	g.logger.Debug("[ObserverGroup.AttachObserver] waiting for lock ...")
	g.lock.Lock()
	defer g.lock.Unlock()
	g.logger.Debug("[ObserverGroup.AttachObserver] got lock ...")

	g.observers = append(g.observers, observer)
}

func (g *ObserverGroup) DetachObserver(observer chan struct{}) bool {
	g.logger.Debug("[ObserverGroup.DetachObserver] waiting for lock ...")
	g.lock.Lock()
	defer g.lock.Unlock()
	g.logger.Debug("[ObserverGroup.DetachObserver] got lock ...")

	for index, attached := range g.observers {
		if attached == observer {
			g.observers[index], g.observers[len(g.observers)-1], g.observers =
				g.observers[len(g.observers)-1], nil, g.observers[:len(g.observers)-1]
			return true
		}
	}
	return false
}

func (g *ObserverGroup) AddObserver() chan struct{} {
	observer := make(chan struct{}, 1)
	g.AttachObserver(observer)
	return observer
}

func (g *ObserverGroup) AddObserverWithTimeout(duration time.Duration) chan struct{} {
	observer := make(chan struct{}, 1)
	timer := time.NewTimer(duration)

	g.AttachObserver(observer)
	go func() {
		<-timer.C
		if g.DetachObserver(observer) {
			select {
			case observer <- struct{}{}:
			default:
			}
		}
	}()

	return observer
}
