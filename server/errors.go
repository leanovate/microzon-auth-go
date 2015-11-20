package server

import (
	"fmt"
	"github.com/go-errors/errors"
)

type HTTPError struct {
	Status  int
	Message string
}

func (err *HTTPError) Error() string {
	return fmt.Sprintf("HTTP error %d: %s", err.Status, err.Message)
}

func NotFound() error {
	return errors.Wrap(&HTTPError{Status: 404, Message: "Not Found"}, 1)
}
