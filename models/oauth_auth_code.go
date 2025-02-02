package models

import (
	"github.com/hocnt84/go-passport/contract"
	"time"
)

type OauthAuthCode struct {
	ID        string `gorm:"primaryKey;type:varchar(36)"`
	UserId    string `gorm:"index:idx_userId_clientId_revoked_expiresAt"`
	ClientId  string `gorm:"index:idx_userId_clientId_revoked_expiresAt"`
	Scopes    string
	Revoked   bool      `gorm:"index:idx_userId_clientId_revoked_expiresAt"`
	ExpiresAt time.Time `gorm:"index:idx_userId_clientId_revoked_expiresAt"`
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
