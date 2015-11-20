package server

import "fmt"

type HTTPError struct {
	Status  int
	Message string
}

func (err *HTTPError) Error() string {
	return fmt.Sprintf("HTTP error %d: %s", err.Status, err.Message)
}

func NotFound() *HTTPError {
	return &HTTPError{Status: 404, Message: "Not Found"}
}
