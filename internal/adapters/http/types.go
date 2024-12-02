package http

type AuthRequest struct {
	UID   string `json:"user_id"`
	Email string `json:"email"`
}

type TokensResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}
