package token

import (
	"encoding/base64"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"time"
)

type TokenMaker struct {
	secretKey string
}

func NewTokenMaker(secretKey string) *TokenMaker {
	return &TokenMaker{}
}

func (maker *TokenMaker) CreateJWTToken(uid, ip, email string, duration time.Duration) (string, *UserClaims, error) {
	claims, err := NewUserClaims(uid, ip, email, duration)
	if err != nil {
		return "", nil, err
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	tokenStr, err := token.SignedString([]byte(maker.secretKey))
	if err != nil {
		return "", nil, fmt.Errorf("error signing token: %v", err)
	}

	return tokenStr, claims, nil
}

func (maker *TokenMaker) VerifyJWTToken(tokenStr string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		_, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("invalid token signing method")
		}

		return []byte(maker.secretKey), nil
	})

	if err != nil {
		return nil, fmt.Errorf("error parsing token: %v", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}

func (maker *TokenMaker) CreateRefreshToken() (string, error) {
	b := make([]byte, 64)

	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)

	_, err := r.Read(b)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func (maker *TokenMaker) HashRefreshToken(refreshToken string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(refreshToken), bcrypt.DefaultCost)
}

func (maker *TokenMaker) VerifyRefreshTokenHash(stored, refreshToken string) (bool, error) {
	err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(refreshToken))
	if err != nil {
		return false, err
	}
	return true, nil
}
