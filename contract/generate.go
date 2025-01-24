package contract

import (
	"context"
	"github.com/golang-jwt/jwt"
	"net/http"
	"time"
)

type (
	// GenerateBasic provide the basis of the generated token data
	GenerateBasic struct {
		OauthClient       OauthClient
		UserID            string
		CreateAt          time.Time
		OauthAccessToken  OauthAccessToken
		Request           *http.Request
		OauthRefreshToken OauthRefreshToken
	}

	// AuthorizeGenerate generate the authorization code interface
	AuthorizeGenerate interface {
		Token(ctx context.Context, data *GenerateBasic) (code string, err error)
	}

	// AccessGenerate generate the access and refresh tokens interface
	AccessGenerate interface {
		Token(ctx context.Context, data *GenerateBasic) (string, error)
		RefreshToken(ctx context.Context, data *GenerateBasic) (string, error)
		Decode(ctx context.Context, accessToken string) *jwt.StandardClaims
	}
)
