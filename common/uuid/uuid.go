package uuid

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

var byteGroups = []uint8{8, 4, 4, 4, 12}

// UUIDv4
type UUID [16]byte

func (u *UUID) String() string {
	bytes := u.Bytes()
	result := hex.EncodeToString(bytes[0 : byteGroups[0]/2])
	start := byteGroups[0] / 2
	for i := 1; i < len(byteGroups); i++ {
		nBytes := byteGroups[i] / 2
		result += "-"
		result += hex.EncodeToString(bytes[start : start+nBytes])
		start += nBytes
	}
	return result
}

func (u *UUID) Bytes() []byte {
	return u[:]
}

// UUIDv4
func New() UUID {
	var uuid UUID
	_, err := rand.Read(uuid.Bytes())
	if err != nil {
		panic(err)
	}
	uuid[6] = (uuid[6] & 0x0f) | (4 << 4)
	uuid[8] = (uuid[8]&(0xff>>2) | (0x02 << 6))
	return uuid
}

func IsUUIDText(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := range 36 {
		switch i {
		case 8, 13, 18, 23:
			if s[i] != '-' {
				return false
			}
		default:
			if !((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >= 'A' && s[i] <= 'F')) {
				return false
			}
		}
	}
	return true
}

func ParseString(str string) (UUID, error) {
	var uuid UUID
	if !IsUUIDText(str) {
		return uuid, errors.New("invalid UUID text")
	}
	text := []byte(str)
	b := uuid.Bytes()
	for _, byteGroup := range byteGroups {
		if text[0] == '-' {
			text = text[1:]
		}
		if _, err := hex.Decode(b[:byteGroup/2], text[:byteGroup]); err != nil {
			return uuid, err
		}
		text = text[byteGroup:]
		b = b[byteGroup/2:]
	}
	return uuid, nil
}
