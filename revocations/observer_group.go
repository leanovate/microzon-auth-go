package revocations

import (
	"github.com/leanovate/microzon-auth-go/logging"
	"sync"
	"time"
)

type ObserveState uint64

// Manage a group of observers (to any kind of resource)
// An observer is just a channel receiving an ObserverGroupState as notification
type ObserverGroup struct {
	logger    logging.Logger
	lock      sync.Mutex
	state     ObserveState
	observers []chan ObserveState
}

// Create a new observer group
// Usually there should be only one per resource
func NewObserverGroup(initialState ObserveState, logger logging.Logger) *ObserverGroup {
	return &ObserverGroup{
		logger: logger.WithContext(map[string]interface{}{"package": "revokations"}),
		state:  initialState,
	}
}

// Notify all observers in the group
// Each observer will be notified only once, after notification the observer will
// be removed from the group
func (g *ObserverGroup) Notify(nextState ObserveState) {
	g.logger.Debug("[ObserverGroup.Notify] waiting for lock ...")
	g.lock.Lock()
	defer g.lock.Unlock()
	g.logger.Debug("[ObserverGroup.Notify] got lock ...")

	g.state = nextState
	for _, observer := range g.observers {
		g.notifyObserver(observer)
	}
	g.observers = g.observers[:0]
	g.logger.Debug("[ObserverGroup.Notify] notified all ...")
}

// Attach an observer to the group
func (g *ObserverGroup) AttachObserver(atState ObserveState, observer chan ObserveState) {
	g.logger.Debug("[ObserverGroup.AttachObserver] waiting for lock ...")
	g.lock.Lock()
	defer g.lock.Unlock()
	g.logger.Debug("[ObserverGroup.AttachObserver] got lock ...")

	if g.state == atState {
		g.observers = append(g.observers, observer)
	} else {
		g.notifyObserver(observer)
	}
}

// Detach an observer from the group
func (g *ObserverGroup) DetachObserver(observer chan ObserveState) bool {
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

// Convenient function to add an observer to the group
// Result is a channel that will receive an empty struct{} on notification
func (g *ObserverGroup) AddObserver(atState ObserveState) chan ObserveState {
	observer := make(chan ObserveState, 1)
	g.AttachObserver(atState, observer)
	return observer
}

// Convenient function to add an observer with timeout to the group
// Result is a channel that is guaranteed to receive a notification within a given amount of time
func (g *ObserverGroup) AddObserverWithTimeout(atState ObserveState, timeout time.Duration) chan ObserveState {
	if timeout == 0 {
		return g.AddObserver(atState)
	}
	observer := make(chan ObserveState, 1)
	timer := time.NewTimer(timeout)

	g.AttachObserver(atState, observer)
	go func() {
		<-timer.C
		if g.DetachObserver(observer) {
			g.notifyObserver(observer)
		}
	}()

	return observer
}

func (g *ObserverGroup) notifyObserver(observer chan ObserveState) {
	select {
	case observer <- g.state:
		close(observer)
	default:
	}
}
