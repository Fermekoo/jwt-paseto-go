package token

import (
	"fmt"
	"time"

	"github.com/o1egl/paseto"
	"golang.org/x/crypto/chacha20poly1305"
)

type PasetoToken struct {
	paseto       paseto.V2
	symetric_key []byte
}

func NewPasetoToken(symetric_key string) (Token, error) {
	if len(symetric_key) != chacha20poly1305.KeySize {
		return nil, fmt.Errorf("invalid key length: must be exactly %d characters", chacha20poly1305.KeySize)
	}

	paseto := &PasetoToken{
		symetric_key: []byte(symetric_key),
	}

	return paseto, nil
}

func (paseto *PasetoToken) CreateToken(user_id int64, duration time.Duration) (string, error) {
	payload, err := NewPayload(user_id, duration)
	if err != nil {
		return "", err
	}

	return paseto.paseto.Encrypt(paseto.symetric_key, payload, nil)
}

func (paseto *PasetoToken) VerifyToken(token string) (*Payload, error) {
	payload := &Payload{}

	err := paseto.paseto.Decrypt(token, paseto.symetric_key, payload, nil)
	if err != nil {
		return nil, ErrInvalid
	}

	err = payload.Valid()
	if err != nil {
		return nil, err
	}

	return payload, nil
}
