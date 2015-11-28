package revocations

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/go-errors/errors"
)

type RawSha256 [32]byte

func RawSha256FromBase64(encoded string) (RawSha256, error) {
	var result RawSha256

	decoded, err := base64.URLEncoding.DecodeString(encoded)

	if err != nil {
		return result, errors.Wrap(err, 0)
	}
	if len(decoded) != 32 {
		return result, errors.Errorf("Invalid sha256: %s", encoded)
	}
	copy(result[:], decoded)

	return result, nil
}

func RawSha256FromData(data string) RawSha256 {
	return RawSha256(sha256.Sum256([]byte(data)))
}

func (r RawSha256) String() string {
	return base64.URLEncoding.EncodeToString(r[:])
}

func (r RawSha256) MarshalJSON() ([]byte, error) {
	return []byte(`"` + r.String() + `"`), nil
}

func (r *RawSha256) UnmarshalJSON(data []byte) error {
	if data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("RawSha256.UnmarshalJSON: Not a json string")
	}
	decoded := make([]byte, base64.URLEncoding.DecodedLen(len(data)-2))
	size, err := base64.URLEncoding.Decode(decoded, data[1:len(data)-1])
	if err != nil {
		return err
	}
	if size != 32 {
		return errors.New("Invalid sha256")
	}
	copy(r[:], decoded)

	return nil
}
