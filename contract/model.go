package contract

import "time"

type (
	AccessToken interface {
		GetOauthAccessToken() OauthAccessToken
		SetOauthAccessToken(OauthAccessToken)

		GetOauthRefreshToken() OauthRefreshToken
		SetOauthRefreshToken(OauthRefreshToken)

		GetAccessToken() string
		SetAccessToken(string)

		GetRefreshToken() string
		SetRefreshToken(string)

		SetScopes(scopes string)
		GetScopes() string
	}
	// OauthClient the oauth client information model interface
	OauthClient interface {
		New() OauthClient
		GetID() string
		GetUserID() string
		GetName() string
		GetSecret() string
		GetProvider() string
		GetRedirect() string
		GetPersonalAccessClient() bool
		GetPasswordClient() bool
		GetRevoked() bool
		VerifyPassword(secret string) bool
	}
	// OauthAuthCode the oauth auth code information model interface
	OauthAuthCode interface {
		New() OauthAuthCode
		GetID() string
		GetUserId() string
		GetClientId() string
		GetScopes() string
		GetRevoked() bool
		GetExpiresAt() time.Time
	}
	// OauthPersonalAccessClient the oauth personal access token information model interface
	OauthPersonalAccessClient interface {
		New() OauthPersonalAccessClient
		GetID() string
		GetClientId() string
	}
	// OauthRefreshToken the oauth refresh token information model interface
	OauthRefreshToken interface {
		New() OauthRefreshToken
		GetID() string
		SetID(string)
		GetAccessTokenId() string
		SetAccessTokenId(string)
		GetRevoked() bool
		SetRevoked(bool)
		GetExpiresAt() time.Time
		SetExpiresAt(time.Time)
	}

	// OauthAccessToken the oauth access token information model interface
	OauthAccessToken interface {
		New() OauthAccessToken
		GetID() string
		SetID(string)
		GetUserId() string
		SetUserId(string)
		GetClientId() string
		SetClientId(string)
		GetName() string
		SetName(string)
		GetScopes() string
		SetScopes(string)
		GetRevoked() bool
		SetRevoked(bool)
		GetExpiresAt() time.Time
		SetExpiresAt(time.Time)
	}

	// ClientPasswordVerifier the password handler interface
	ClientPasswordVerifier interface {
		VerifyPassword(string) bool
	}
)
