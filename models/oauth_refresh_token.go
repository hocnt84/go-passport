package models

import (
	"github.com/google/uuid"
	"github.com/hocnt84/go-passport/contract"
	"time"
)

type OauthRefreshToken struct {
	ID            string
	AccessTokenId string
	Revoked       bool
	ExpiresAt     time.Time
}

// TableName overrides the table name used by User to `oauth_clients`
func (OauthRefreshToken) TableName() string {
	return "oauth_refresh_tokens"
}

func (t *OauthRefreshToken) SetID(s string) {
	t.ID = s
}

func (t *OauthRefreshToken) SetAccessTokenId(s string) {
	t.AccessTokenId = s
}

func (t *OauthRefreshToken) SetRevoked(b bool) {
	t.Revoked = b
}

func (t *OauthRefreshToken) SetExpiresAt(s time.Time) {
	t.ExpiresAt = s
}

// New create to token model instance
func (t *OauthRefreshToken) New() contract.OauthRefreshToken {
	return NewOauthRefreshToken()
}

// NewOauthRefreshToken New OauthRefreshToken create to token model instance
func NewOauthRefreshToken() *OauthRefreshToken {
	return &OauthRefreshToken{
		ID:        uuid.NewString(),
		ExpiresAt: time.Now().UTC(),
	}
}

func (t *OauthRefreshToken) GetID() string {
	return t.ID
}

func (t *OauthRefreshToken) GetAccessTokenId() string {
	return t.AccessTokenId
}

func (t *OauthRefreshToken) GetRevoked() bool {
	return t.Revoked
}

func (t *OauthRefreshToken) GetExpiresAt() time.Time {
	return t.ExpiresAt
}
