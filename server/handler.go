package server

import (
	"context"
	"github.com/hocnt84/go-passport/constant"
	"github.com/hocnt84/go-passport/contract"
	"github.com/hocnt84/go-passport/errors"
	"github.com/hocnt84/go-passport/models"
	"net/http"
	"time"
)

type (
	// ClientInfoHandler get client info from request
	ClientInfoHandler func(r *http.Request) (client contract.OauthClient, err error)

	// ClientAuthorizedHandler check the client allows to use this authorization grant type
	ClientAuthorizedHandler func(clientID string, grant constant.GrantType) (allowed bool, err error)

	// ClientScopeHandler check the client allows to use scope
	ClientScopeHandler func(tgr *contract.TokenGenerateRequest) (allowed bool, err error)

	// UserAuthorizationHandler get user id from request authorization
	UserAuthorizationHandler func(w http.ResponseWriter, r *http.Request) (userID string, err error)

	// PasswordAuthorizationHandler get user id from username and password
	PasswordAuthorizationHandler func(ctx context.Context, client contract.OauthClient, username, password string) (userID string, err error)

	// RefreshingScopeHandler check the scope of the refreshing token
	RefreshingScopeHandler func(tgr *contract.TokenGenerateRequest, oldScope string) (allowed bool, err error)

	// RefreshingValidationHandler check if refresh_token is still valid. eg no revocation or other
	RefreshingValidationHandler func(ti contract.OauthAccessToken) (allowed bool, err error)

	// ResponseErrorHandler response error handing
	ResponseErrorHandler func(re *errors.Response)

	// InternalErrorHandler internal error handing
	InternalErrorHandler func(err error) (re *errors.Response)

	// PreRedirectErrorHandler is used to override "redirect-on-error" behavior
	PreRedirectErrorHandler func(w http.ResponseWriter, req *AuthorizeRequest, err error) error

	// AuthorizeScopeHandler set the authorized scope
	AuthorizeScopeHandler func(w http.ResponseWriter, r *http.Request) (scope string, err error)

	// AccessTokenExpHandler set expiration date for the access token
	AccessTokenExpHandler func(w http.ResponseWriter, r *http.Request) (exp time.Duration, err error)

	// ExtensionFieldsHandler in response to the access token with the extension of the field
	ExtensionFieldsHandler func(ti contract.AccessToken) (fieldsValue map[string]interface{})

	// ResponseTokenHandler response token handing
	ResponseTokenHandler func(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error
)

// ClientBasicHandler get client data from basic authorization
func ClientBasicHandler(r *http.Request) (contract.OauthClient, error) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return nil, errors.ErrInvalidClient
	}
	return &models.OauthClient{
		ID:     username,
		Secret: password,
	}, nil
}
