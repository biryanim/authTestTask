package main

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"time"
)

func GenerateRefreshToken() (string, error) {
	b := make([]byte, 64)

	s := rand.NewSource(time.Now().UnixNano())
	r := rand.New(s)

	_, err := r.Read(b)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

func main() {
	fmt.Println(GenerateRefreshToken())
}
