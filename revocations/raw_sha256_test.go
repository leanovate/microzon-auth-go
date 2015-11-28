package revocations

import (
	"encoding/base64"
	"encoding/json"
	. "github.com/smartystreets/goconvey/convey"
	"testing"
)

func TestRawSha256(t *testing.T) {
	type TestVO struct {
		Sha256 RawSha256 `json:"sha256"`
	}

	Convey("Given sha256 of data", t, func() {
		sha256 := RawSha256FromData("some data")

		So([32]byte(sha256), ShouldResemble, [32]byte{
			0x13, 0x7, 0x99, 0xe, 0x6b, 0xa5, 0xca, 0x14,
			0x5e, 0xb3, 0x5e, 0x99, 0x18, 0x2a, 0x9b, 0xec,
			0x46, 0x53, 0x1b, 0xc5, 0x4d, 0xdf, 0x65, 0x6a,
			0x60, 0x2c, 0x78, 0xf, 0xa0, 0x24, 0xd, 0xee})

		Convey("When sha256 is encoded and decoded", func() {
			encoded := sha256.String()

			Println(base64.URLEncoding.DecodedLen(len(encoded)))
			decoded, err := RawSha256FromBase64(encoded)

			So(err, ShouldBeNil)
			So(decoded, ShouldResemble, sha256)
		})

		Convey("When sha256 is encoded and decoded to json", func() {
			expected := &TestVO{
				Sha256: sha256,
			}
			jsonStr, err := json.Marshal(expected)
			So(err, ShouldBeNil)
			var actual TestVO
			err = json.Unmarshal([]byte(jsonStr), &actual)
			So(err, ShouldBeNil)
			So(actual, ShouldResemble, *expected)
		})
	})
}
