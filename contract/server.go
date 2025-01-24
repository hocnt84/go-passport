package contract

import (
	"context"
	"github.com/hocnt84/go-passport/constant"
	"net/http"
)

type Server interface {
	HandleTokenRequest(w http.ResponseWriter, r *http.Request) error
	ValidationTokenRequest(r *http.Request) (constant.GrantType, *TokenGenerateRequest, error)
	GetAccessToken(ctx context.Context, gt constant.GrantType, tgr *TokenGenerateRequest) (AccessToken, error)
	//tokenError(w http.ResponseWriter, err error) error
	//token(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error
	GetErrorData(err error) (map[string]interface{}, int, http.Header)
	GetTokenData(accessToken AccessToken) map[string]interface{}
	HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) error
	GetAuthorizeData(rt constant.ResponseType, ti AccessToken) map[string]interface{}
	//GetAuthorizeToken(ctx context.Context, req *AuthorizeRequest) (AccessToken, error)
	CheckCodeChallengeMethod(codeChallengeMethod constant.CodeChallengeMethod) bool
	CheckResponseType(responseType constant.ResponseType) bool
	CheckGrantType(gt constant.GrantType) bool
}
