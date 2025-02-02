package models

import (
	"github.com/hocnt84/go-passport/contract"
	"golang.org/x/crypto/bcrypt"
)

type OauthClient struct {
	ID                   string `gorm:"primaryKey;type:varchar(36)"`
	UserID               string `gorm:"size:36;index;default:NULL"`
	Name                 string `size:"size:250"`
	Secret               string `gorm:"size:150;default:NULL"`
	Provider             string `gorm:"size:250;default:NULL"`
	Redirect             string `gorm:"type:text"`
	PersonalAccessClient bool
	PasswordClient       bool
	Revoked              bool
}

// TableName overrides the table name used by User to `oauth_clients`
func (OauthClient) TableName() string {
	return "oauth_clients"
}

func (o *OauthClient) New() contract.OauthClient {
	return NewOauthClient()
}

func NewOauthClient() *OauthClient {
	return &OauthClient{}
}

func (o *OauthClient) GetID() string {
	return o.ID
}

func (o *OauthClient) GetUserID() string {
	return o.UserID
}

func (o *OauthClient) GetName() string {
	return o.Name
}

func (o *OauthClient) GetSecret() string {
	return o.Secret
}

func (o *OauthClient) GetProvider() string {
	return o.Provider
}

func (o *OauthClient) GetRedirect() string {
	return o.Redirect
}

func (o *OauthClient) GetPersonalAccessClient() bool {
	return o.PersonalAccessClient
}

func (o *OauthClient) GetPasswordClient() bool {
	return o.PasswordClient
}
func (o *OauthClient) GetRevoked() bool {
	return o.Revoked
}

func (o *OauthClient) VerifyPassword(secret string) bool {
	return bcrypt.CompareHashAndPassword([]byte(o.Secret), []byte(secret)) == nil
}
