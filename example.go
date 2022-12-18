package main

import (
	"fmt"
	"time"

	"github.com/Fermekoo/jwt-paseto-go/token"
)

func main() {
	secret_key := "123456789012345678901234567890aq"
	token_maker, _ := token.NewPasetoToken(secret_key)
	// token_maker, _ := token.NewJwtToken(secret_key)

	token, _ := token_maker.CreateToken(10, time.Minute)

	fmt.Println(token)

}
