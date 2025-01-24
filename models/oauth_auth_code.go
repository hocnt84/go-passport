package models

import (
	"github.com/hocnt84/go-passport/contract"
	"time"
)

type OauthAuthCode struct {
	ID        string
	UserId    string
	ClientId  string
	Scopes    string
	Revoked   bool
	ExpiresAt time.Time
}

func NewOauthAuthCode() *OauthAuthCode {
	return &OauthAuthCode{}
}

// TableName overrides the table name used by User to `oauth_clients`
func (OauthAuthCode) TableName() string {
	return "oauth_auth_codes"
}

func (o *OauthAuthCode) New() contract.OauthAuthCode {
	return NewOauthAuthCode()
}

// GetID oauth auth code ID
func (o *OauthAuthCode) GetID() string {
	return o.ID
}

// GetUserId oauth auth code UserId
func (o *OauthAuthCode) GetUserId() string {
	return o.UserId
}

// GetClientId oauth auth code ClientId
func (o *OauthAuthCode) GetClientId() string {
	return o.ClientId
}

// GetScopes oauth auth code Scopes
func (o *OauthAuthCode) GetScopes() string {
	return o.Scopes
}

// GetRevoked oauth auth code Revoked
func (o *OauthAuthCode) GetRevoked() bool {
	return o.Revoked
}

// GetExpiresAt oauth auth code ExpiresAt
func (o *OauthAuthCode) GetExpiresAt() time.Time {
	return o.ExpiresAt
}
