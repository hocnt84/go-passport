package server

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hocnt84/go-passport/constant"
	"github.com/hocnt84/go-passport/contract"
	"github.com/hocnt84/go-passport/errors"
	"net/http"
	"net/url"
	"time"
)

// NewDefaultServer create a default authorization server
func NewDefaultServer(manager contract.Manager) *Server {
	return NewServer(NewConfig(), manager)
}

// NewServer create authorization server
func NewServer(cfg *Config, manager contract.Manager) *Server {
	srv := &Server{
		Config:  cfg,
		Manager: manager,
	}

	// default handler
	srv.ClientInfoHandler = ClientBasicHandler

	srv.UserAuthorizationHandler = func(w http.ResponseWriter, r *http.Request) (string, error) {
		return "", errors.ErrAccessDenied
	}

	srv.PasswordAuthorizationHandler = func(ctx context.Context, client contract.OauthClient, username, password string) (string, error) {
		return "", errors.ErrAccessDenied
	}
	return srv
}

// Server Provide authorization server
type Server struct {
	Config                       *Config
	Manager                      contract.Manager
	ClientInfoHandler            ClientInfoHandler
	ClientAuthorizedHandler      ClientAuthorizedHandler
	ClientScopeHandler           ClientScopeHandler
	UserAuthorizationHandler     UserAuthorizationHandler
	PasswordAuthorizationHandler PasswordAuthorizationHandler
	RefreshingValidationHandler  RefreshingValidationHandler
	PreRedirectErrorHandler      PreRedirectErrorHandler
	RefreshingScopeHandler       RefreshingScopeHandler
	ResponseErrorHandler         ResponseErrorHandler
	InternalErrorHandler         InternalErrorHandler
	ExtensionFieldsHandler       ExtensionFieldsHandler
	AccessTokenExpHandler        AccessTokenExpHandler
	AuthorizeScopeHandler        AuthorizeScopeHandler
	ResponseTokenHandler         ResponseTokenHandler
}

// HandleTokenRequest token request handling
func (s *Server) HandleTokenRequest(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	gt, tgr, err := s.ValidationTokenRequest(r)
	if err != nil {
		return err
	}

	ti, err := s.GetAccessToken(ctx, gt, tgr)
	if err != nil {
		return err
	}

	return s.token(w, s.GetTokenData(ti), nil)
}

// ValidationTokenRequest the token request validation
func (s *Server) ValidationTokenRequest(r *http.Request) (constant.GrantType, *contract.TokenGenerateRequest, error) {
	if v := r.Method; !(v == "POST" ||
		(s.Config.AllowGetAccessRequest && v == "GET")) {
		return "", nil, errors.ErrInvalidRequest
	}

	gt := constant.GrantType(r.FormValue("grant_type"))
	if gt.String() == "" {
		return "", nil, errors.ErrUnsupportedGrantType
	}

	client, err := s.ClientInfoHandler(r)
	if err != nil {
		return "", nil, err
	}

	tgr := &contract.TokenGenerateRequest{
		Client:       client,
		ClientID:     client.GetID(),
		ClientSecret: r.FormValue("client_secret"),
		Request:      r,
	}

	switch gt {
	case constant.AuthorizationCode:
		tgr.RedirectURI = r.FormValue("redirect_uri")
		tgr.Code = r.FormValue("code")
		if tgr.RedirectURI == "" ||
			tgr.Code == "" {
			return "", nil, errors.ErrInvalidRequest
		}
		tgr.CodeVerifier = r.FormValue("code_verifier")
		if s.Config.ForcePKCE && tgr.CodeVerifier == "" {
			return "", nil, errors.ErrInvalidRequest
		}
	case constant.PasswordCredentials:
		tgr.Scope = r.FormValue("scope")
		username, password := r.FormValue("username"), r.FormValue("password")
		if username == "" || password == "" {
			return "", nil, errors.ErrInvalidRequest
		}

		userID, err := s.PasswordAuthorizationHandler(r.Context(), tgr.Client, username, password)
		if err != nil {
			return "", nil, err
		} else if userID == "" {
			return "", nil, errors.ErrInvalidGrant
		}
		tgr.UserID = userID
	case constant.ClientCredentials:
		tgr.Scope = r.FormValue("scope")
	case constant.Refreshing:
		tgr.RefreshToken = r.FormValue("refresh_token")
		claims := s.Manager.GetAccessGenerate().Decode(r.Context(), tgr.RefreshToken)
		if claims == nil {
			return "", nil, errors.ErrInvalidRequest
		}
		tgr.RefreshTokenId = claims.Id
		tgr.Scope = r.FormValue("scope")
		if tgr.RefreshTokenId == "" {
			return "", nil, errors.ErrInvalidRequest
		}
	}
	return gt, tgr, nil
}

// GetAccessToken access token
func (s *Server) GetAccessToken(ctx context.Context, gt constant.GrantType, tgr *contract.TokenGenerateRequest) (contract.AccessToken,
	error) {
	if allowed := s.CheckGrantType(gt); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	if fn := s.ClientAuthorizedHandler; fn != nil {
		allowed, err := fn(tgr.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	switch gt {
	case constant.AuthorizationCode:
		ti, err := s.Manager.GenerateAccessToken(ctx, gt, tgr)
		if err != nil {
			switch err {
			case errors.ErrInvalidAuthorizeCode, errors.ErrInvalidCodeChallenge, errors.ErrMissingCodeChallenge:
				return nil, errors.ErrInvalidGrant
			case errors.ErrInvalidClient:
				return nil, errors.ErrInvalidClient
			default:
				return nil, err
			}
		}
		return ti, nil
	case constant.PasswordCredentials, constant.ClientCredentials:
		if fn := s.ClientScopeHandler; fn != nil {
			allowed, err := fn(tgr)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}
		return s.Manager.GenerateAccessToken(ctx, gt, tgr)
	case constant.Refreshing:
		// check scope
		if scopeFn := s.RefreshingScopeHandler; tgr.Scope != "" && scopeFn != nil {
			rti, err := s.Manager.LoadRefreshToken(ctx, tgr.RefreshToken)
			if err != nil {
				if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
					return nil, errors.ErrInvalidGrant
				}
				return nil, err
			}

			allowed, err := scopeFn(tgr, rti.GetScopes())
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}

		if validationFn := s.RefreshingValidationHandler; validationFn != nil {
			rti, err := s.Manager.LoadRefreshToken(ctx, tgr.RefreshToken)
			if err != nil {
				if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
					return nil, errors.ErrInvalidGrant
				}
				return nil, err
			}
			allowed, err := validationFn(rti)
			if err != nil {
				return nil, err
			} else if !allowed {
				return nil, errors.ErrInvalidScope
			}
		}

		ti, err := s.Manager.RefreshAccessToken(ctx, tgr)
		if err != nil {
			if err == errors.ErrInvalidRefreshToken || err == errors.ErrExpiredRefreshToken {
				return nil, errors.ErrInvalidGrant
			}
			return nil, err
		}
		return ti, nil
	}

	return nil, errors.ErrUnsupportedGrantType
}

func (s *Server) tokenError(w http.ResponseWriter, err error) error {
	data, statusCode, header := s.GetErrorData(err)
	return s.token(w, data, header, statusCode)
}

func (s *Server) token(w http.ResponseWriter, data map[string]interface{}, header http.Header, statusCode ...int) error {
	if fn := s.ResponseTokenHandler; fn != nil {
		return fn(w, data, header, statusCode...)
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	for key := range header {
		w.Header().Set(key, header.Get(key))
	}

	status := http.StatusOK
	if len(statusCode) > 0 && statusCode[0] > 0 {
		status = statusCode[0]
	}

	w.WriteHeader(status)
	return json.NewEncoder(w).Encode(data)
}

// GetErrorData get error response data
func (s *Server) GetErrorData(err error) (map[string]interface{}, int, http.Header) {
	var re errors.Response
	if v, ok := errors.Descriptions[err]; ok {
		re.Error = err
		re.Description = v
		re.StatusCode = errors.StatusCodes[err]
	} else {
		if fn := s.InternalErrorHandler; fn != nil {
			if v := fn(err); v != nil {
				re = *v
			}
		}

		if re.Error == nil {
			re.Error = errors.ErrServerError
			re.Description = errors.Descriptions[errors.ErrServerError]
			re.StatusCode = errors.StatusCodes[errors.ErrServerError]
		}
	}

	if fn := s.ResponseErrorHandler; fn != nil {
		fn(&re)
	}

	data := make(map[string]interface{})
	if err := re.Error; err != nil {
		data["error"] = err.Error()
	}

	if v := re.ErrorCode; v != 0 {
		data["error_code"] = v
	}

	if v := re.Description; v != "" {
		data["error_description"] = v
	}

	if v := re.URI; v != "" {
		data["error_uri"] = v
	}

	statusCode := http.StatusInternalServerError
	if v := re.StatusCode; v > 0 {
		statusCode = v
	}

	return data, statusCode, re.Header
}

// GetTokenData token data
func (s *Server) GetTokenData(accessToken contract.AccessToken) map[string]interface{} {
	data := map[string]interface{}{
		"access_token": accessToken.GetAccessToken(),
		"token_type":   s.Config.TokenType,
		"expires_in":   accessToken.GetOauthAccessToken().GetExpiresAt().UTC().Unix() - time.Now().Unix(),
	}

	if scopes := accessToken.GetScopes(); len(scopes) > 0 {
		data["scopes"] = scopes
	}

	if refresh := accessToken.GetRefreshToken(); refresh != "" {
		data["refresh_token"] = refresh
	}

	if fn := s.ExtensionFieldsHandler; fn != nil {
		ext := fn(accessToken)
		for k, v := range ext {
			if _, ok := data[k]; ok {
				continue
			}
			data[k] = v
		}
	}
	return data
}

// HandleAuthorizeRequest the authorization request handling
func (s *Server) HandleAuthorizeRequest(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()

	req, err := s.ValidationAuthorizeRequest(r)
	if err != nil {
		return s.handleError(w, req, err)
	}

	// user authorization
	userID, err := s.UserAuthorizationHandler(w, r)
	if err != nil {
		return s.handleError(w, req, err)
	} else if userID == "" {
		return nil
	}
	req.UserID = userID

	// specify the scope of authorization
	if fn := s.AuthorizeScopeHandler; fn != nil {
		scope, err := fn(w, r)
		if err != nil {
			return err
		} else if scope != "" {
			req.Scope = scope
		}
	}

	// specify the expiration time of access token
	if fn := s.AccessTokenExpHandler; fn != nil {
		exp, err := fn(w, r)
		if err != nil {
			return err
		}
		req.AccessTokenExp = exp
	}

	ti, err := s.GetAuthorizeToken(ctx, req)
	if err != nil {
		return s.handleError(w, req, err)
	}

	// If the redirect URI is empty, the default domain provided by the client is used.
	if req.RedirectURI == "" {
		client, err := s.Manager.GetClient(ctx, req.ClientID)
		if err != nil {
			return err
		}
		print(client)
		req.RedirectURI = "client.GetDomain()"
	}

	return s.redirect(w, req, s.GetAuthorizeData(req.ResponseType, ti))
}

// GetAuthorizeData get authorization response data
func (s *Server) GetAuthorizeData(rt constant.ResponseType, ti contract.AccessToken) map[string]interface{} {
	if rt == constant.Code {
		return map[string]interface{}{
			"code": "ti.GetCode()",
		}
	}
	return s.GetTokenData(ti)
}

// GetAuthorizeToken get authorization token(code)
func (s *Server) GetAuthorizeToken(ctx context.Context, req *AuthorizeRequest) (contract.AccessToken, error) {
	// check the client allows the grant type
	if fn := s.ClientAuthorizedHandler; fn != nil {
		gt := constant.AuthorizationCode
		if req.ResponseType == constant.Token {
			gt = constant.Implicit
		}

		allowed, err := fn(req.ClientID, gt)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrUnauthorizedClient
		}
	}

	tgr := &contract.TokenGenerateRequest{
		ClientID:       req.ClientID,
		UserID:         req.UserID,
		RedirectURI:    req.RedirectURI,
		Scope:          req.Scope,
		AccessTokenExp: req.AccessTokenExp,
		Request:        req.Request,
	}

	// check the client allows the authorized scope
	if fn := s.ClientScopeHandler; fn != nil {
		allowed, err := fn(tgr)
		if err != nil {
			return nil, err
		} else if !allowed {
			return nil, errors.ErrInvalidScope
		}
	}

	tgr.CodeChallenge = req.CodeChallenge
	tgr.CodeChallengeMethod = req.CodeChallengeMethod

	return s.Manager.GenerateAuthToken(ctx, req.ResponseType, tgr)
}

func (s *Server) handleError(w http.ResponseWriter, req *AuthorizeRequest, err error) error {
	if fn := s.PreRedirectErrorHandler; fn != nil {
		return fn(w, req, err)
	}

	return s.redirectError(w, req, err)
}

func (s *Server) redirectError(w http.ResponseWriter, req *AuthorizeRequest, err error) error {
	if req == nil {
		return err
	}

	data, _, _ := s.GetErrorData(err)
	return s.redirect(w, req, data)
}

func (s *Server) redirect(w http.ResponseWriter, req *AuthorizeRequest, data map[string]interface{}) error {
	uri, err := s.GetRedirectURI(req, data)
	if err != nil {
		return err
	}

	w.Header().Set("Location", uri)
	w.WriteHeader(302)
	return nil
}

// GetRedirectURI get redirect uri
func (s *Server) GetRedirectURI(req *AuthorizeRequest, data map[string]interface{}) (string, error) {
	u, err := url.Parse(req.RedirectURI)
	if err != nil {
		return "", err
	}

	q := u.Query()
	if req.State != "" {
		q.Set("state", req.State)
	}

	for k, v := range data {
		q.Set(k, fmt.Sprint(v))
	}

	switch req.ResponseType {
	case constant.Code:
		u.RawQuery = q.Encode()
	case constant.Token:
		u.RawQuery = ""
		fragment, err := url.QueryUnescape(q.Encode())
		if err != nil {
			return "", err
		}
		u.Fragment = fragment
	}

	return u.String(), nil
}

// ValidationAuthorizeRequest the authorization request validation
func (s *Server) ValidationAuthorizeRequest(r *http.Request) (*AuthorizeRequest, error) {
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	if !(r.Method == "GET" || r.Method == "POST") ||
		clientID == "" {
		return nil, errors.ErrInvalidRequest
	}

	resType := constant.ResponseType(r.FormValue("response_type"))
	if resType.String() == "" {
		return nil, errors.ErrUnsupportedResponseType
	} else if allowed := s.CheckResponseType(resType); !allowed {
		return nil, errors.ErrUnauthorizedClient
	}

	cc := r.FormValue("code_challenge")
	if cc == "" && s.Config.ForcePKCE {
		return nil, errors.ErrCodeChallengeRquired
	}
	if cc != "" && (len(cc) < 43 || len(cc) > 128) {
		return nil, errors.ErrInvalidCodeChallengeLen
	}

	ccm := constant.CodeChallengeMethod(r.FormValue("code_challenge_method"))
	// set default
	if ccm == "" {
		ccm = constant.CodeChallengePlain
	}
	if ccm != "" && !s.CheckCodeChallengeMethod(ccm) {
		return nil, errors.ErrUnsupportedCodeChallengeMethod
	}

	req := &AuthorizeRequest{
		RedirectURI:         redirectURI,
		ResponseType:        resType,
		ClientID:            clientID,
		State:               r.FormValue("state"),
		Scope:               r.FormValue("scope"),
		Request:             r,
		CodeChallenge:       cc,
		CodeChallengeMethod: ccm,
	}
	return req, nil
}

// CheckCodeChallengeMethod checks for allowed code challenge method
func (s *Server) CheckCodeChallengeMethod(codeChallengeMethod constant.CodeChallengeMethod) bool {
	for _, c := range s.Config.AllowedCodeChallengeMethods {
		if c == codeChallengeMethod {
			return true
		}
	}
	return false
}

// CheckResponseType check allows response type
func (s *Server) CheckResponseType(responseType constant.ResponseType) bool {
	for _, art := range s.Config.AllowedResponseTypes {
		if art == responseType {
			return true
		}
	}
	return false
}

// CheckGrantType check allows grant type
func (s *Server) CheckGrantType(gt constant.GrantType) bool {
	for _, agt := range s.Config.AllowedGrantTypes {
		if agt == gt {
			return true
		}
	}
	return false
}
