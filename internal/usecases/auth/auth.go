package auth

import (
	"github.com/biryanim/authTestTask/internal/entities/token"
	"os"
	"time"
)

type Auth struct {
	jwt     *token.JWTMaker
	refresh string
}

func New() *Auth {
	key := os.Getenv("SECRET_KEY")
	return &Auth{
		jwt: token.NewJWTMaker(key),
	}
}

func (a *Auth) GenerateJWTToken(uid string, email, ip string, duration time.Duration) (string, *token.UserClaims, error) {
	return a.jwt.CreateToken(uid, email, ip, duration)
}
