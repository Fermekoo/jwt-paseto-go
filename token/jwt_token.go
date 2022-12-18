package token

import (
	"errors"
	"fmt"
	"time"

	jwt_lib "github.com/golang-jwt/jwt/v4"
)

const min_secret_key = 32

type JwtToken struct {
	secret_key string
}

func NewJwtToken(secret_key string) (Token, error) {
	if len(secret_key) != min_secret_key {
		return nil, fmt.Errorf("invalid key length: must be exactly %d characters", min_secret_key)
	}

	jwt := &JwtToken{
		secret_key: secret_key,
	}

	return jwt, nil
}

func (jwt *JwtToken) CreateToken(user_id int64, duration time.Duration) (string, error) {
	payload, err := NewPayload(user_id, duration)
	if err != nil {
		return "", nil
	}

	token := jwt_lib.NewWithClaims(jwt_lib.SigningMethodHS256, payload)

	return token.SignedString([]byte(jwt.secret_key))
}

func (jwt *JwtToken) VerifyToken(token string) (*Payload, error) {
	keyFunc := func(token *jwt_lib.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt_lib.SigningMethodHMAC)
		if !ok {
			return nil, ErrInvalid
		}
		return []byte(jwt.secret_key), nil
	}

	jwt_token, err := jwt_lib.ParseWithClaims(token, &Payload{}, keyFunc)
	if err != nil {
		verr, ok := err.(*jwt_lib.ValidationError)
		if ok && errors.Is(verr.Inner, ErrExpired) {
			return nil, ErrExpired
		}

		return nil, ErrInvalid
	}

	payload, ok := jwt_token.Claims.(*Payload)
	if !ok {
		return nil, ErrInvalid
	}

	return payload, nil
}
