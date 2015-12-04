package store

import (
	"crypto/x509"
	"github.com/leanovate/microzon-auth-go/common"
)

// Agent storage backend (also applies to the server
type AgentStore interface {
	// Find/lookup a certificate by its thumbprint
	FindCertificate(thumbprint string) (*x509.Certificate, error)

	// Get all certificates
	AllCertificates() ([]*x509.Certificate, error)

	// Set a listener for revocations
	// The implementation is supposed to send all existing revocations at once
	SetRevocationsListener(listener common.RevocationsListener) error

	// Close the store
	Close()
}
