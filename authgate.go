package authgate

import (
	"encoding/json"
	"errors"
	"net/http"
)

var ErrInvalidRequest = errors.New("invalid request")
var ErrUnauthorizedRequest = errors.New("unauthorized request")

type UserInfo struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
	Name   string `json:"name"`
}

type AuthGateClient struct {
	url string
}

func NewClient(url string) *AuthGateClient {
	return &AuthGateClient{url}
}

func (c *AuthGateClient) VerifySession(sessionID string, userID string) (UserInfo, error) {
	resp, err := http.Get(c.url + "/verify-session?sessionid=" + sessionID + "&userid=" + userID)
	if err != nil {
		return UserInfo{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 400 {
		return UserInfo{}, ErrInvalidRequest
	}

	if resp.StatusCode == 401 {
		return UserInfo{}, ErrUnauthorizedRequest
	}

	var result UserInfo
	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return UserInfo{}, err
	}

	return result, nil
}
