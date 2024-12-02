package token

import (
	"github.com/golang-jwt/jwt/v5"
	"time"
)

type UserClaims struct {
	ID    string `json:"user_id"`
	Ip    string `json:"ip"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

func NewUserClaims(uid, ip, email string, duration time.Duration) (*UserClaims, error) {
	return &UserClaims{
		ID:    uid,
		Ip:    ip,
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        uid,
			Subject:   email,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
		},
	}, nil
}
