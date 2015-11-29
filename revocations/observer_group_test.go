package revocations

import (
	"fmt"
	"github.com/leanovate/microzon-auth-go/logging"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
)

func ShouldBlock(actual interface{}, expected ...interface{}) string {
	channel, actualIsChannel := actual.(chan ObserverGroupState)

	if !actualIsChannel {
		return fmt.Sprintf("%v should be a channel", actual)
	}

	select {
	case msg := <-channel:
		return fmt.Sprintf("%v did not block, but received %v", channel, msg)
	default:
		return ""
	}
}

func ShouldNotBlock(actual interface{}, expected ...interface{}) string {
	channel, actualIsChannel := actual.(chan ObserverGroupState)

	if !actualIsChannel {
		return fmt.Sprintf("%v should be a channel", actual)
	}

	select {
	case <-channel:
		return ""
	default:
		return fmt.Sprintf("%v did block", channel)
	}

}

func TestObserverGroup(t *testing.T) {
	Convey("Given an observer group", t, func() {
		observerGroup := NewObserverGroup(0, logging.NewSimpleLoggerNull())

		Convey("And two Observers", func() {
			observer1 := observerGroup.AddObserver(0)
			observer2 := observerGroup.AddObserver(0)

			Convey("Then neither should have received a notify yet", func() {
				So(observer1, ShouldBlock)
				So(observer2, ShouldBlock)
			})

			Convey("When notfication is triggered", func() {
				observerGroup.Notify(1)

				So(observer1, ShouldNotBlock)
				So(observer2, ShouldNotBlock)
				So(observerGroup.state, ShouldEqual, 1)
				So(observerGroup.observers, ShouldHaveLength, 0)

				Convey("When notification is triggered a second time", func() {
					observerGroup.Notify(2)

					So(observer1, ShouldNotBlock)
					So(observer2, ShouldNotBlock)
					So(observerGroup.state, ShouldEqual, 2)
				})
			})
		})

		Convey("When observer is added to different state", func() {
			observer := observerGroup.AddObserver(1)

			So(observer, ShouldNotBlock)
			So(observerGroup.state, ShouldEqual, 0)
			So(observerGroup.observers, ShouldHaveLength, 0)
		})

		Convey("When three observers are attached", func() {
			observer1 := make(chan ObserverGroupState, 1)
			observer2 := make(chan ObserverGroupState, 1)
			observer3 := make(chan ObserverGroupState, 1)

			observerGroup.AttachObserver(0, observer1)
			observerGroup.AttachObserver(0, observer2)
			observerGroup.AttachObserver(0, observer3)

			So(observer1, ShouldBlock)
			So(observer2, ShouldBlock)
			So(observer3, ShouldBlock)

			Convey("When notfication is triggered", func() {
				observerGroup.Notify(0)

				So(observer1, ShouldNotBlock)
				So(observer2, ShouldNotBlock)
				So(observer3, ShouldNotBlock)
			})

			Convey("When observer1 is detached", func() {
				result := observerGroup.DetachObserver(observer2)

				So(result, ShouldBeTrue)

				Convey("When notfication is triggered", func() {
					observerGroup.Notify(1)

					So(observer1, ShouldNotBlock)
					So(observer2, ShouldBlock)
					So(observer3, ShouldNotBlock)
				})

				Convey("When observer2 is detached a second time", func() {
					result := observerGroup.DetachObserver(observer2)

					So(result, ShouldBeFalse)
				})
			})
		})

		Convey("When observers are added with timeout", func() {
			observer1 := observerGroup.AddObserverWithTimeout(0, 1 * time.Second)
			observer2 := observerGroup.AddObserverWithTimeout(0, 1 * time.Second)

			Convey("Then neither should have received a notify yet", func() {
				So(observer1, ShouldBlock)
				So(observer2, ShouldBlock)
			})

			Convey("When notfication is triggered", func() {
				observerGroup.Notify(1)

				So(observer1, ShouldNotBlock)
				So(observer2, ShouldNotBlock)
			})

			Convey("When timeout is reached", func() {
				time.Sleep(2 * time.Second)

				So(observer1, ShouldNotBlock)
				So(observer2, ShouldNotBlock)
				So(observerGroup.observers, ShouldHaveLength, 0)

				Convey("When notification is triggered after timeout", func() {
					observerGroup.Notify(1)

					So(observer1, ShouldNotBlock)
					So(observer2, ShouldNotBlock)
					So(observerGroup.state, ShouldEqual, 1)
				})
			})
		})
	})
}
