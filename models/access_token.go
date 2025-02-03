package models

import (
	"github.com/hocnt84/go-passport/contract"
)

type AccessToken struct {
	oauthAccessToken  contract.OauthAccessToken
	oauthRefreshToken contract.OauthRefreshToken
	accessToken       string
	refreshToken      string
	scopes            string
}

func (t *AccessToken) SetScopes(scopes string) {
	t.scopes = scopes
}

func (t *AccessToken) GetScopes() string {
	return t.scopes
}

func (t *AccessToken) GetAccessToken() string {
	return t.accessToken
}

func (t *AccessToken) SetAccessToken(s string) {
	t.accessToken = s
}

func (t *AccessToken) GetRefreshToken() string {
	return t.refreshToken
}

func (t *AccessToken) SetRefreshToken(s string) {
	t.refreshToken = s
}

func (t *AccessToken) GetOauthAccessToken() contract.OauthAccessToken {
	return t.oauthAccessToken
}

func (t *AccessToken) GetOauthRefreshToken() contract.OauthRefreshToken {
	return t.oauthRefreshToken
}

func (t *AccessToken) SetOauthAccessToken(accessToken contract.OauthAccessToken) {
	t.oauthAccessToken = accessToken
}

func (t *AccessToken) SetOauthRefreshToken(refreshToken contract.OauthRefreshToken) {
	t.oauthRefreshToken = refreshToken
}

// New create to token model instance
func (t *AccessToken) New() contract.AccessToken {
	return NewAccessToken()
}

// NewAccessToken New NewToken NewToken create to token model instance
func NewAccessToken() *AccessToken {
	return &AccessToken{}
}
