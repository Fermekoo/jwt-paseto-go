package token

import (
	"fmt"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func randomString(n int) string {
	alphabet := "abcdefghijklmnopqrstuvwxyz"
	var sb strings.Builder
	k := len(alphabet)

	for i := 0; i < n; i++ {
		c := alphabet[rand.Intn(k)]
		sb.WriteByte(c)
	}

	return sb.String()
}

func TestPasetoToken(t *testing.T) {
	paseto, err := NewPasetoToken(randomString(32))
	require.NoError(t, err)

	user_id := rand.Int63n(10)
	duration := time.Minute
	issued_at := time.Now()
	expired_at := issued_at.Add(duration)

	token, err := paseto.CreateToken(user_id, duration)
	fmt.Println(token)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	payload, err := paseto.VerifyToken(token)
	require.NoError(t, err)
	require.NotEmpty(t, payload)
	require.NotZero(t, payload.ID)
	require.Equal(t, user_id, payload.UserID)
	require.WithinDuration(t, issued_at, payload.IssuedAt, time.Second)
	require.WithinDuration(t, expired_at, payload.ExpiredAt, time.Second)
}

func TestExpiredPasetoToken(t *testing.T) {
	paseto, err := NewPasetoToken(randomString(32))
	require.NoError(t, err)

	token, err := paseto.CreateToken(rand.Int63n(10), -time.Minute)
	require.NoError(t, err)

	payload, err := paseto.VerifyToken(token)
	require.Error(t, err)
	require.EqualError(t, err, ErrExpired.Error())
	require.Nil(t, payload)
}

func TestInvalidLengthKeyPaseto(t *testing.T) {
	paseto, err := NewPasetoToken(randomString(31))
	require.Error(t, err)
	require.Nil(t, paseto)
}
