package contract

import (
	"context"
	"github.com/hocnt84/go-passport/config"
	"github.com/hocnt84/go-passport/constant"
	"net/http"
	"time"
)

type (
	// ValidateURIHandler validates that redirectURI is contained in baseURI
	ValidateURIHandler      func(baseURI, redirectURI string) error
	ExtractExtensionHandler func(*TokenGenerateRequest)
)

// TokenGenerateRequest provide to generate the token request parameters
type TokenGenerateRequest struct {
	ClientID            string
	ClientSecret        string
	UserID              string
	RedirectURI         string
	Scope               string
	Code                string
	CodeChallenge       string
	CodeChallengeMethod constant.CodeChallengeMethod
	RefreshTokenId      string
	RefreshToken        string
	CodeVerifier        string
	AccessTokenExp      time.Duration
	Request             *http.Request
}

// Manager authorization management interface
type Manager interface {
	// GetClient get the client information
	GetClient(ctx context.Context, clientID string) (cli OauthClient, err error)

	// GenerateAuthToken generate the authorization token(code)
	GenerateAuthToken(ctx context.Context, rt constant.ResponseType, tgr *TokenGenerateRequest) (authToken AccessToken, err error)

	// GenerateAccessToken generate the access token
	GenerateAccessToken(ctx context.Context, gt constant.GrantType, tgr *TokenGenerateRequest) (accessToken AccessToken, err error)

	// RefreshAccessToken refreshing an access token
	RefreshAccessToken(ctx context.Context, tgr *TokenGenerateRequest) (accessToken AccessToken, err error)

	// RemoveAccessToken use the access token to delete the token information
	RemoveAccessToken(ctx context.Context, access string) (err error)

	// RemoveRefreshToken use the refresh token to delete the token information
	RemoveRefreshToken(ctx context.Context, refresh string) (err error)

	// LoadAccessToken according to the access token for corresponding token information
	LoadAccessToken(ctx context.Context, access string) (OauthAccessToken, error)

	// LoadRefreshToken according to the refresh token for corresponding token information
	LoadRefreshToken(ctx context.Context, refresh string) (OauthAccessToken, error)

	SetAuthorizeCodeExp(exp time.Duration)
	SetAuthorizeCodeTokenCfg(cfg *config.Config)
	SetImplicitTokenCfg(cfg *config.Config)
	SetPasswordTokenCfg(cfg *config.Config)
	SetClientTokenCfg(cfg *config.Config)
	SetRefreshTokenCfg(cfg *config.RefreshingConfig)
	SetValidateURIHandler(handler ValidateURIHandler)
	SetExtractExtensionHandler(handler ExtractExtensionHandler)
	SetClientDataAccess(store OauthClientDataAccess)
	SetRefreshTokenDataAccess(store OauthRefreshTokenDataAccess)
	SetAccessTokenDataAccess(store OauthAccessTokenDataAccess)
	MustAccessTokenDataAccess(store OauthAccessTokenDataAccess, err error)
	MustClientDataAccess(store OauthClientDataAccess, err error)
	MustRefreshTokenDataAccess(store OauthRefreshTokenDataAccess, err error)
	GetAccessGenerate() AccessGenerate
	//MapAuthorizeGenerate(gen passport.AuthorizeGenerate)
	//MapAccessGenerate(gen passport.AccessGenerate)
}
