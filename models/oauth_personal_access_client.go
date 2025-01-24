package models

import "github.com/hocnt84/go-passport/contract"

type OauthPersonalAccessClient struct {
	ID       string
	ClientID string
}

func NewOauthPersonalAccessClient() *OauthPersonalAccessClient {
	return &OauthPersonalAccessClient{}
}

// TableName overrides the table name used by User to `oauth_clients`
func (OauthPersonalAccessClient) TableName() string {
	return "oauth_personal_access_clients"
}

func (o *OauthPersonalAccessClient) New() contract.OauthPersonalAccessClient {
	return NewOauthPersonalAccessClient()
}

func (o *OauthPersonalAccessClient) GetID() string {
	return o.ID
}

func (o *OauthPersonalAccessClient) GetClientId() string {
	return o.ClientID
}
