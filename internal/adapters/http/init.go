package http

import (
	"encoding/json"
	"github.com/biryanim/authTestTask/internal/entities/token"
	"github.com/go-chi/chi/v5"
	"net/http"
	"time"
)

type AuthUseCase interface {
}

type Adapter struct {
	auth  AuthUseCase
	token token.TokenMaker
}

func New() *Adapter {
	return &Adapter{}
}

func StartServer(a *Adapter) {
	r := chi.NewRouter()

	r.Post("/generate-tokens", a.generateTokens)
	r.Post("refresh-tokens", a.renewAccessTokens)
}

func (a *Adapter) generateTokens(w http.ResponseWriter, r *http.Request) {
	var auth AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&auth); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if auth.UID == "" {
		http.Error(w, "UID is required", http.StatusBadRequest)
		return
	}

	ip := r.RemoteAddr
	token, _, err := a.token.CreateJWTToken(auth.UID, ip, auth.Email, 15*time.Minute)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	refreshToken, err := a.token.CreateRefreshToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp := TokensResponse{
		AccessToken:  token,
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func (a *Adapter) renewAccessTokens(w http.ResponseWriter, r *http.Request) {

}
