package revocations

import (
	"fmt"
	"github.com/leanovate/microzon-auth-go/logging"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
	"time"
)

func ShouldBlock(actual interface{}, expected ...interface{}) string {
	channel, actualIsChannel := actual.(chan struct{})

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
	channel, actualIsChannel := actual.(chan struct{})

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
		observerGroup := NewObserverGroup(logging.NewSimpleLoggerNull())

		Convey("And two Observers", func() {
			observer1 := observerGroup.AddObserver()
			observer2 := observerGroup.AddObserver()

			Convey("Then neither should have received a notify yet", func() {
				So(observer1, ShouldBlock)
				So(observer2, ShouldBlock)
			})

			Convey("When notfication is triggered", func() {
				observerGroup.Notify()

				So(observer1, ShouldNotBlock)
				So(observer2, ShouldNotBlock)

				Convey("When notification is triggered a second time", func() {
					observerGroup.Notify()

					So(observer1, ShouldBlock)
					So(observer2, ShouldBlock)
				})
			})
		})

		Convey("When three observers are attached", func() {
			observer1 := make(chan struct{}, 1)
			observer2 := make(chan struct{}, 1)
			observer3 := make(chan struct{}, 1)

			observerGroup.AttachObserver(observer1)
			observerGroup.AttachObserver(observer2)
			observerGroup.AttachObserver(observer3)

			So(observer1, ShouldBlock)
			So(observer2, ShouldBlock)
			So(observer3, ShouldBlock)

			Convey("When notfication is triggered", func() {
				observerGroup.Notify()

				So(observer1, ShouldNotBlock)
				So(observer2, ShouldNotBlock)
				So(observer3, ShouldNotBlock)
			})

			Convey("When observer1 is detached", func() {
				result := observerGroup.DetachObserver(observer2)

				So(result, ShouldBeTrue)

				Convey("When notfication is triggered", func() {
					observerGroup.Notify()

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
			observer1 := observerGroup.AddObserverWithTimeout(1 * time.Second)
			observer2 := observerGroup.AddObserverWithTimeout(1 * time.Second)

			Convey("Then neither should have received a notify yet", func() {
				So(observer1, ShouldBlock)
				So(observer2, ShouldBlock)
			})

			Convey("When notfication is triggered", func() {
				observerGroup.Notify()

				So(observer1, ShouldNotBlock)
				So(observer2, ShouldNotBlock)
			})

			Convey("When timeout is reached", func() {
				time.Sleep(2 * time.Second)

				So(observer1, ShouldNotBlock)
				So(observer2, ShouldNotBlock)

				Convey("When notification is triggered after timeout", func() {
					observerGroup.Notify()

					So(observer1, ShouldBlock)
					So(observer2, ShouldBlock)
				})
			})
		})
	})
}
