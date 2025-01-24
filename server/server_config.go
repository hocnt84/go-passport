package server

import (
	"context"
	"github.com/hocnt84/go-passport/constant"
	"github.com/hocnt84/go-passport/contract"
	"github.com/hocnt84/go-passport/errors"
	"net/http"
	"strings"
)

// SetTokenType token type
func (s *Server) SetTokenType(tokenType string) {
	s.Config.TokenType = tokenType
}

// SetAllowGetAccessRequest to allow GET requests for the token
func (s *Server) SetAllowGetAccessRequest(allow bool) {
	s.Config.AllowGetAccessRequest = allow
}

// SetAllowedResponseType allow the authorization types
func (s *Server) SetAllowedResponseType(types ...constant.ResponseType) {
	s.Config.AllowedResponseTypes = types
}

// SetAllowedGrantType allow the grant types
func (s *Server) SetAllowedGrantType(types ...constant.GrantType) {
	s.Config.AllowedGrantTypes = types
}

// SetClientInfoHandler get client info from request
func (s *Server) SetClientInfoHandler(handler ClientInfoHandler) {
	s.ClientInfoHandler = handler
}

// SetClientAuthorizedHandler check the client allows to use this authorization grant type
func (s *Server) SetClientAuthorizedHandler(handler ClientAuthorizedHandler) {
	s.ClientAuthorizedHandler = handler
}

// SetClientScopeHandler check the client allows to use scope
func (s *Server) SetClientScopeHandler(handler ClientScopeHandler) {
	s.ClientScopeHandler = handler
}

// SetUserAuthorizationHandler get user id from request authorization
func (s *Server) SetUserAuthorizationHandler(handler UserAuthorizationHandler) {
	s.UserAuthorizationHandler = handler
}

// SetPasswordAuthorizationHandler get user id from username and password
func (s *Server) SetPasswordAuthorizationHandler(handler PasswordAuthorizationHandler) {
	s.PasswordAuthorizationHandler = handler
}

// SetRefreshingScopeHandler check the scope of the refreshing token
func (s *Server) SetRefreshingScopeHandler(handler RefreshingScopeHandler) {
	s.RefreshingScopeHandler = handler
}

// SetRefreshingValidationHandler check if refresh_token is still valid. eg no revocation or other
func (s *Server) SetRefreshingValidationHandler(handler RefreshingValidationHandler) {
	s.RefreshingValidationHandler = handler
}

// SetResponseErrorHandler response error handling
func (s *Server) SetResponseErrorHandler(handler ResponseErrorHandler) {
	s.ResponseErrorHandler = handler
}

// SetInternalErrorHandler internal error handling
func (s *Server) SetInternalErrorHandler(handler InternalErrorHandler) {
	s.InternalErrorHandler = handler
}

// SetPreRedirectErrorHandler sets the PreRedirectErrorHandler in current Server instance
func (s *Server) SetPreRedirectErrorHandler(handler PreRedirectErrorHandler) {
	s.PreRedirectErrorHandler = handler
}

// SetExtensionFieldsHandler in response to the access token with the extension of the field
func (s *Server) SetExtensionFieldsHandler(handler ExtensionFieldsHandler) {
	s.ExtensionFieldsHandler = handler
}

// SetAccessTokenExpHandler set expiration date for the access token
func (s *Server) SetAccessTokenExpHandler(handler AccessTokenExpHandler) {
	s.AccessTokenExpHandler = handler
}

// SetAuthorizeScopeHandler set scope for the access token
func (s *Server) SetAuthorizeScopeHandler(handler AuthorizeScopeHandler) {
	s.AuthorizeScopeHandler = handler
}

// SetResponseTokenHandler response token handing
func (s *Server) SetResponseTokenHandler(handler ResponseTokenHandler) {
	s.ResponseTokenHandler = handler
}

// BearerAuth parse bearer token
func (s *Server) BearerAuth(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	prefix := "Bearer "
	token := ""

	if auth != "" && strings.HasPrefix(auth, prefix) {
		token = auth[len(prefix):]
	} else {
		token = r.FormValue("access_token")
	}

	return token, token != ""
}

// ValidationBearerToken validation the bearer tokens
// https://tools.ietf.org/html/rfc6750
func (s *Server) ValidationBearerToken(r *http.Request) (contract.OauthAccessToken, error) {
	ctx := r.Context()

	accessToken, ok := s.BearerAuth(r)
	if !ok {
		return nil, errors.ErrInvalidAccessToken
	}
	claims := s.Manager.GetAccessGenerate().Decode(context.Background(), accessToken)
	return s.Manager.LoadAccessToken(ctx, claims.Id)
}
