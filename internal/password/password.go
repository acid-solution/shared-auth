package password

import (
	"errors"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

var ErrInvalid = errors.New("password must contain 8 to 72 bytes")

type Hasher struct {
	cost int
}

func NewHasher(cost int) Hasher {
	return Hasher{cost: cost}
}

func Validate(value string) error {
	if !utf8.ValidString(value) || len([]byte(value)) < 8 || len([]byte(value)) > 72 {
		return ErrInvalid
	}
	return nil
}

func (h Hasher) Hash(value string) (string, error) {
	if err := Validate(value); err != nil {
		return "", err
	}
	result, err := bcrypt.GenerateFromPassword([]byte(value), h.cost)
	return string(result), err
}

func (h Hasher) Compare(hash, value string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(value)) == nil
}
