package contract

import "context"

type (
	// OauthClientDataAccess the client information storage interface
	OauthClientDataAccess interface {
		// Migration init schema
		Migration() error

		// GetByID according to the ID for the client information
		GetByID(ctx context.Context, id string) (OauthClient, error)
	}
	// OauthRefreshTokenDataAccess the refresh token information storage interface
	OauthRefreshTokenDataAccess interface {
		// Migration init schema
		Migration() error

		// Create and store the new token information
		Create(ctx context.Context, info OauthRefreshToken) error

		GetAccessToken(ctx context.Context, refreshTokenId string) (OauthAccessToken, error)

		RemoveByRefreshTokenId(ctx context.Context, refreshTokenId string) error

		RemoveByAccessTokenId(ctx context.Context, refreshTokenId string) error
	}
	// OauthAccessTokenDataAccess the token information storage interface
	OauthAccessTokenDataAccess interface {
		// Migration init schema
		Migration() error

		// Create and store the new token information
		Create(ctx context.Context, info OauthAccessToken) error

		// GetAccessTokenByRefreshToken get access token via refresh token
		GetAccessTokenByRefreshToken(ctx context.Context, refreshTokenId string) (OauthAccessToken, error)

		// RemoveByAccessTokenId use the access token to delete the token information
		RemoveByAccessTokenId(ctx context.Context, accessTokenId string) error

		// GetByAccess use the access token for token information data
		GetByAccess(ctx context.Context, access string) (OauthAccessToken, error)
	}
)
