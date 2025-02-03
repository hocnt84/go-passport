package models

import (
	"github.com/hocnt84/go-passport/contract"
	"time"
)

type OauthAccessToken struct {
	ID        string    `gorm:"primaryKey;type:varchar(36)"`
	UserId    string    `gorm:"index:idx_userId_clientId_revoked_expiresAt"`
	ClientId  string    `gorm:"index:idx_userId_clientId_revoked_expiresAt"`
	Name      string    `gorm:"type:varchar(150)"`
	Scopes    string    `gorm:"type:text"`
	Revoked   bool      `gorm:"index:idx_userId_clientId_revoked_expiresAt"`
	ExpiresAt time.Time `gorm:"index:idx_userId_clientId_revoked_expiresAt"`
}

// TableName overrides the table name used by User to `oauth_clients`
func (OauthAccessToken) TableName() string {
	return "oauth_access_tokens"
}

// New create to token model instance
func (t *OauthAccessToken) New() contract.OauthAccessToken {
	return NewOauthAccessToken()
}

// NewOauthAccessToken New NewToken NewToken create to token model instance
func NewOauthAccessToken() *OauthAccessToken {
	return &OauthAccessToken{}
}

func (t *OauthAccessToken) SetID(s string) {
	t.ID = s
}

func (t *OauthAccessToken) SetUserId(s string) {
	t.UserId = s
}

func (t *OauthAccessToken) SetClientId(s string) {
	t.ClientId = s
}

func (t *OauthAccessToken) SetName(s string) {
	t.Name = s
}

func (t *OauthAccessToken) SetScopes(scopes string) {
	t.Scopes = scopes
}

func (t *OauthAccessToken) SetRevoked(revoked bool) {
	t.Revoked = revoked
}

func (t *OauthAccessToken) SetExpiresAt(expiresAt time.Time) {
	t.ExpiresAt = expiresAt
}

// GetID oauth auth code ID
func (t *OauthAccessToken) GetID() string {
	return t.ID
}
func (t *OauthAccessToken) GetUserId() string {
	return t.UserId
}
func (t *OauthAccessToken) GetClientId() string {
	return t.ClientId
}
func (t *OauthAccessToken) GetName() string {
	return t.Name
}
func (t *OauthAccessToken) GetScopes() string {
	return t.Scopes
}
func (t *OauthAccessToken) GetRevoked() bool {
	return t.Revoked
}
func (t *OauthAccessToken) GetExpiresAt() time.Time {
	return t.ExpiresAt
}
