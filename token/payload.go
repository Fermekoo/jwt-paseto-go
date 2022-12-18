package token

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrExpired = errors.New("token has expired")
	ErrInvalid = errors.New("token is invalid")
)

type Payload struct {
	ID        uuid.UUID `json:"id"`
	UserID    int64     `json:"user_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

func NewPayload(user_id int64, duration time.Duration) (*Payload, error) {
	tokenId, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	issued_at := time.Now()
	payload := &Payload{
		ID:        tokenId,
		UserID:    user_id,
		IssuedAt:  issued_at,
		ExpiredAt: issued_at.Add(duration),
	}

	return payload, nil
}

func (p *Payload) Valid() error {
	if time.Now().After(p.ExpiredAt) {
		return ErrExpired
	}

	return nil
}
