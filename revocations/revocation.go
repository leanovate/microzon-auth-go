package revocations

import (
	"encoding/base64"
	"github.com/go-errors/errors"
	"time"
)

type RawSha256 [32]byte

func NewRawSha256(encoded string) (RawSha256, error) {
	var result RawSha256
	size, err := base64.URLEncoding.Decode(result[:], []byte(encoded))

	if err != nil {
		return result, errors.Wrap(err, 0)
	}
	if size != 32 {
		return result, errors.Errorf("Invalid sha256: %s", encoded)
	}
	return result, nil
}

func (r RawSha256) String() string {
	return base64.URLEncoding.EncodeToString(r[:])
}

type Revocation struct {
	Version   uint64
	Sha256    RawSha256
	ExpiresAt time.Time
}

func NewRevocation(version uint64, sha256 RawSha256, expiresAt time.Time) *Revocation {
	return &Revocation{
		Version:   version,
		Sha256:    sha256,
		ExpiresAt: expiresAt,
	}
}
