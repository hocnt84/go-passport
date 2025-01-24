package server

import (
	"github.com/hocnt84/go-passport/constant"
	"net/http"
	"time"
)

// Config configuration parameters
type Config struct {
	TokenType                   string                  // token type
	AllowGetAccessRequest       bool                    // to allow GET requests for the token
	AllowedResponseTypes        []constant.ResponseType // allow the authorization type
	AllowedGrantTypes           []constant.GrantType    // allow the grant type
	AllowedCodeChallengeMethods []constant.CodeChallengeMethod
	ForcePKCE                   bool
}

// NewConfig create to configuration instance
func NewConfig() *Config {
	return &Config{
		TokenType:            "Bearer",
		AllowedResponseTypes: []constant.ResponseType{constant.Code, constant.Token},
		AllowedGrantTypes: []constant.GrantType{
			constant.AuthorizationCode,
			constant.PasswordCredentials,
			constant.ClientCredentials,
			constant.Refreshing,
		},
		AllowedCodeChallengeMethods: []constant.CodeChallengeMethod{
			constant.CodeChallengePlain,
			constant.CodeChallengeS256,
		},
	}
}

// AuthorizeRequest authorization request
type AuthorizeRequest struct {
	ResponseType        constant.ResponseType
	ClientID            string
	Scope               string
	RedirectURI         string
	State               string
	UserID              string
	CodeChallenge       string
	CodeChallengeMethod constant.CodeChallengeMethod
	AccessTokenExp      time.Duration
	Request             *http.Request
}
