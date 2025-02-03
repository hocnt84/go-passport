package manage

import (
	"context"
	"github.com/google/uuid"
	"github.com/hocnt84/go-passport/config"
	"github.com/hocnt84/go-passport/constant"
	"github.com/hocnt84/go-passport/contract"
	"github.com/hocnt84/go-passport/generates"
	"github.com/hocnt84/go-passport/models"
	"github.com/hocnt84/go-passport/util"
	"time"
)

// NewDefaultManager create to default authorization management instance
func NewDefaultManager() *Manager {
	m := NewManager()
	// default implementation
	m.MapAuthorizeGenerate(generates.NewAuthorizeGenerate())
	m.MapAccessGenerate(generates.NewAccessGenerate())

	return m
}

// NewManager create to authorization management instance
func NewManager() *Manager {
	return &Manager{
		grantTypeConfig: make(map[constant.GrantType]*config.Config),
		validateURI:     util.DefaultValidateURI,
	}
}

// Manager provide authorization management
type Manager struct {
	codeExp                     time.Duration
	grantTypeConfig             map[constant.GrantType]*config.Config
	refreshingConfig            *config.RefreshingConfig
	validateURI                 contract.ValidateURIHandler
	extractExtension            contract.ExtractExtensionHandler
	authorizeGenerate           contract.AuthorizeGenerate
	accessGenerate              contract.AccessGenerate
	oauthAccessTokenDataAccess  contract.OauthAccessTokenDataAccess
	oauthRefreshTokenDataAccess contract.OauthRefreshTokenDataAccess
	oauthClientDataAccess       contract.OauthClientDataAccess
}

func (m *Manager) GetAccessGenerate() contract.AccessGenerate {
	return m.accessGenerate
}

func (m *Manager) MustClientDataAccess(store contract.OauthClientDataAccess, err error) {
	if err != nil {
		panic(err)
	}
	m.oauthClientDataAccess = store
}

func (m *Manager) SetRefreshTokenDataAccess(store contract.OauthRefreshTokenDataAccess) {
	m.oauthRefreshTokenDataAccess = store
}

func (m *Manager) SetAuthorizeCodeExp(exp time.Duration) {
	m.codeExp = exp
}

func (m *Manager) SetAuthorizeCodeTokenCfg(cfg *config.Config) {
	m.grantTypeConfig[constant.AuthorizationCode] = cfg
}

func (m *Manager) SetImplicitTokenCfg(cfg *config.Config) {
	m.grantTypeConfig[constant.Implicit] = cfg
}

func (m *Manager) SetPasswordTokenCfg(cfg *config.Config) {
	m.grantTypeConfig[constant.PasswordCredentials] = cfg
}

func (m *Manager) SetClientTokenCfg(cfg *config.Config) {
	m.grantTypeConfig[constant.ClientCredentials] = cfg
}

func (m *Manager) SetRefreshTokenCfg(cfg *config.RefreshingConfig) {
	m.refreshingConfig = cfg
}

func (m *Manager) SetValidateURIHandler(handler contract.ValidateURIHandler) {
	m.validateURI = handler
}

func (m *Manager) SetExtractExtensionHandler(handler contract.ExtractExtensionHandler) {
	m.extractExtension = handler
}

// MapAuthorizeGenerate mapping the authorize code generate interface
func (m *Manager) MapAuthorizeGenerate(gen contract.AuthorizeGenerate) {
	m.authorizeGenerate = gen
}

// MapAccessGenerate mapping the access token generate interface
func (m *Manager) MapAccessGenerate(gen contract.AccessGenerate) {
	m.accessGenerate = gen
}

// MustAccessTokenDataAccess mandatory mapping the token store interface
func (m *Manager) MustAccessTokenDataAccess(store contract.OauthAccessTokenDataAccess, err error) {
	if err != nil {
		panic(err)
	}
	m.oauthAccessTokenDataAccess = store
}

// MustRefreshTokenDataAccess mandatory mapping the token store interface
func (m *Manager) MustRefreshTokenDataAccess(store contract.OauthRefreshTokenDataAccess, err error) {
	if err != nil {
		panic(err)
	}
	m.oauthRefreshTokenDataAccess = store
}

// SetClientDataAccess the client store interface
func (m *Manager) SetClientDataAccess(store contract.OauthClientDataAccess) {
	m.oauthClientDataAccess = store
}

func (m *Manager) SetAccessTokenDataAccess(store contract.OauthAccessTokenDataAccess) {
	m.oauthAccessTokenDataAccess = store
}

func (m *Manager) GetClient(ctx context.Context, clientID string) (cli contract.OauthClient, err error) {
	return m.oauthClientDataAccess.GetByID(ctx, clientID)
}

func (m *Manager) GenerateAuthToken(ctx context.Context, responseType constant.ResponseType, tokenGenerateRequest *contract.TokenGenerateRequest) (authToken contract.AccessToken, err error) {
	client, clientError := m.GetClient(ctx, tokenGenerateRequest.ClientID)
	if clientError != nil {
		return nil, clientError
	} else if tokenGenerateRequest.RedirectURI != "" {
		if err := m.validateURI(client.GetRedirect(), tokenGenerateRequest.RedirectURI); err != nil {
			return nil, err
		}
	}
	responseAccessToken := models.NewAccessToken()
	//oauthAccessToken := models.NewOauthAccessToken()
	//switch responseType {
	//case constant.Code:
	//	codeExp := m.codeExp
	//	if codeExp == 0 {
	//		codeExp = DefaultCodeExp
	//	}
	//	ti.SetCodeCreateAt(createAt)
	//	ti.SetCodeExpiresIn(codeExp)
	//	if exp := tgr.AccessTokenExp; exp > 0 {
	//		ti.SetAccessExpiresIn(exp)
	//	}
	//	if tgr.CodeChallenge != "" {
	//		ti.SetCodeChallenge(tokenGenerateRequest.CodeChallenge)
	//		ti.SetCodeChallengeMethod(tokenGenerateRequest.CodeChallengeMethod)
	//	}
	//
	//	tv, err := m.authorizeGenerate.Token(ctx, td)
	//	if err != nil {
	//		return nil, err
	//	}
	//	ti.SetCode(tv)
	//}
	return responseAccessToken, nil
}

func (m *Manager) GenerateAccessToken(ctx context.Context, gt constant.GrantType, tgr *contract.TokenGenerateRequest) (contract.AccessToken, error) {

	//if tgr.RedirectURI != "" {
	//	if err := m.validateURI(cli.GetDomain(), tgr.RedirectURI); err != nil {
	//		return nil, err
	//	}
	//}
	responseAccessToken := models.NewAccessToken()

	oauthAccessToken := models.NewOauthAccessToken()

	// set access token expires
	grantConfig := m.grantConfig(gt)

	// Set Expires At
	expiresAt := grantConfig.AccessTokenExp

	if accessTokenExp := tgr.AccessTokenExp; accessTokenExp > 0 {
		expiresAt = accessTokenExp
	}

	// Set ID
	oauthAccessToken.SetID(uuid.NewString())

	// Set ClientId
	oauthAccessToken.SetClientId(tgr.Client.GetID())

	// Set Name
	oauthAccessToken.SetName(tgr.Client.GetName())

	// Set Expires At
	oauthAccessToken.SetExpiresAt(time.Now().UTC().Add(expiresAt))

	oauthRefreshToken := models.NewOauthRefreshToken()

	// Set access token id
	oauthRefreshToken.SetAccessTokenId(oauthAccessToken.GetID())

	RefreshTokenExpiresAt := grantConfig.RefreshTokenExp

	// Set Expires At
	oauthRefreshToken.SetExpiresAt(time.Now().UTC().Add(RefreshTokenExpiresAt))

	generateBasic := &contract.GenerateBasic{
		OauthClient:       tgr.Client,
		UserID:            tgr.UserID,
		CreateAt:          time.Now().UTC(),
		OauthAccessToken:  oauthAccessToken,
		Request:           tgr.Request,
		OauthRefreshToken: oauthRefreshToken,
	}
	accessToken, accessTokenError := m.accessGenerate.Token(ctx, generateBasic)
	if accessTokenError != nil {
		return nil, accessTokenError
	}

	responseAccessToken.SetAccessToken(accessToken)
	responseAccessToken.SetOauthAccessToken(oauthAccessToken)

	// Save access token to DB
	oauthAccessTokenError := m.oauthAccessTokenDataAccess.Create(ctx, oauthAccessToken)
	if oauthAccessTokenError != nil {
		return nil, oauthAccessTokenError
	}
	if grantConfig.IsGenerateRefresh {
		refreshToken, refreshTokenError := m.accessGenerate.RefreshToken(ctx, generateBasic)
		if refreshTokenError != nil {
			return nil, refreshTokenError
		}
		responseAccessToken.SetOauthRefreshToken(oauthRefreshToken)
		responseAccessToken.SetRefreshToken(refreshToken)

		// Save refresh token to DB
		_ = m.oauthRefreshTokenDataAccess.Create(ctx, oauthRefreshToken)
	}
	return responseAccessToken, nil
}

func (m *Manager) RefreshAccessToken(ctx context.Context, tgr *contract.TokenGenerateRequest) (accessToken contract.AccessToken, err error) {
	oauthAccessTokenOld, oauthFAccessTokenOldError := m.LoadRefreshToken(ctx, tgr.RefreshTokenId)
	if oauthFAccessTokenOldError != nil {
		return nil, oauthFAccessTokenOldError
	}
	oauthClient, oauthClientError := m.GetClient(ctx, oauthAccessTokenOld.GetClientId())
	if oauthClientError != nil {
		return nil, oauthClientError
	}

	// Init model access token
	responseAccessToken := models.NewAccessToken()

	// Init model oauth access token
	oauthAccessToken := models.NewOauthAccessToken()

	// Get grant configuration
	grantConfig := m.grantConfig(constant.PasswordCredentials)

	// Get Expires At
	expiresAt := grantConfig.AccessTokenExp

	// Get Expires At
	if accessTokenExp := tgr.AccessTokenExp; accessTokenExp > 0 {
		expiresAt = accessTokenExp
	}

	// Set ID
	oauthAccessToken.SetID(uuid.NewString())

	// Set ClientId
	oauthAccessToken.SetClientId(oauthClient.GetID())

	// Set Name
	oauthAccessToken.SetName(oauthClient.GetName())

	// Set Expires At
	oauthAccessToken.SetExpiresAt(time.Now().UTC().Add(expiresAt * time.Second))

	// Init oauth refresh token
	oauthRefreshToken := models.NewOauthRefreshToken()

	// Set access token id
	oauthRefreshToken.SetAccessTokenId(oauthAccessToken.GetID())

	// Get refresh token expires
	RefreshTokenExpiresAt := grantConfig.RefreshTokenExp

	// Set expires at
	oauthRefreshToken.SetExpiresAt(time.Now().UTC().Add(RefreshTokenExpiresAt * time.Second))

	// Init generate basic
	generateBasic := &contract.GenerateBasic{
		OauthClient:       oauthClient,
		UserID:            tgr.UserID,
		CreateAt:          time.Now().UTC(),
		OauthAccessToken:  oauthAccessToken,
		Request:           tgr.Request,
		OauthRefreshToken: oauthRefreshToken,
	}

	// Get access token
	token, tokenError := m.accessGenerate.Token(ctx, generateBasic)
	if tokenError != nil {
		return nil, tokenError
	}

	responseAccessToken.SetAccessToken(token)
	responseAccessToken.SetOauthAccessToken(oauthAccessToken)

	// Save access token to DB
	oauthAccessTokenError := m.oauthAccessTokenDataAccess.Create(ctx, oauthAccessToken)
	if oauthAccessTokenError != nil {
		return nil, oauthAccessTokenError
	}

	if grantConfig.IsGenerateRefresh {
		refreshToken, refreshTokenError := m.accessGenerate.RefreshToken(ctx, generateBasic)
		if refreshTokenError != nil {
			return nil, refreshTokenError
		}
		responseAccessToken.SetOauthRefreshToken(oauthRefreshToken)
		responseAccessToken.SetRefreshToken(refreshToken)

		// Save refresh token to DB
		_ = m.oauthRefreshTokenDataAccess.Create(ctx, oauthRefreshToken)
	}

	// Delete old token
	_ = m.RemoveAccessToken(ctx, oauthAccessTokenOld.GetID())
	_ = m.RemoveRefreshToken(ctx, oauthAccessTokenOld.GetID())

	return responseAccessToken, nil
}

func (m *Manager) RemoveAccessToken(ctx context.Context, accessTokenId string) error {
	return m.oauthAccessTokenDataAccess.RemoveByAccessTokenId(ctx, accessTokenId)
}

func (m *Manager) RemoveRefreshToken(ctx context.Context, refreshTokenId string) error {
	return m.oauthRefreshTokenDataAccess.RemoveByAccessTokenId(ctx, refreshTokenId)
}

func (m *Manager) LoadAccessToken(ctx context.Context, accessTokenId string) (contract.OauthAccessToken, error) {
	return m.oauthAccessTokenDataAccess.GetByAccess(ctx, accessTokenId)
}

func (m *Manager) LoadRefreshToken(ctx context.Context, refreshTokenId string) (contract.OauthAccessToken, error) {
	return m.oauthAccessTokenDataAccess.GetAccessTokenByRefreshToken(ctx, refreshTokenId)
}

// get grant type config
func (m *Manager) grantConfig(grantType constant.GrantType) *config.Config {
	if c, ok := m.grantTypeConfig[grantType]; ok && c != nil {
		return c
	}
	switch grantType {
	case constant.AuthorizationCode:
		return config.DefaultAuthorizeCodeTokenCfg
	case constant.Implicit:
		return config.DefaultImplicitTokenCfg
	case constant.PasswordCredentials:
		return config.DefaultPasswordTokenCfg
	case constant.ClientCredentials:
		return config.DefaultClientTokenCfg
	}
	return &config.Config{}
}
