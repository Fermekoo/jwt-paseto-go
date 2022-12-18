package token

import "time"

type Token interface {
	CreateToken(user_id int64, duration time.Duration) (string, error)
	VerifyToken(token string) (*Payload, error)
}
