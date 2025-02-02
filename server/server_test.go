package server_test

import (
	"context"
	"github.com/gavv/httpexpect"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/hocnt84/go-passport/config"
	"github.com/hocnt84/go-passport/constant"
	"github.com/hocnt84/go-passport/contract"
	"github.com/hocnt84/go-passport/errors"
	"github.com/hocnt84/go-passport/generates"
	"github.com/hocnt84/go-passport/manage"
	"github.com/hocnt84/go-passport/models"
	"github.com/hocnt84/go-passport/server"
	"github.com/hocnt84/go-passport/store"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"net/http"
	"net/http/httptest"
	"testing"
)

var (
	srv            *server.Server
	httpTestServer *httptest.Server
	manager        *manage.Manager
	userID         = uuid.NewString()
	clientSecret   = "11111111"
	username       = "jxx"
	password       = "jxx"
	db             *gorm.DB
)

func InitDatabase() {
	//db, _ := gorm.Open(sqlite.Open("gorm.db"), &gorm.Config{})
	db, _ = gorm.Open(mysql.Open("root:@tcp(localhost:3306)/identity_db2?multiStatements=true&parseTime=true"))
}

func init() {
	manager = manage.NewDefaultManager()
	InitDatabase()
	manager.SetClientDataAccess(store.NewOauthClientStore(db))
}

func testServer(t *testing.T, w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/token":
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	case "/authorize":
		err := srv.HandleAuthorizeRequest(w, r)
		if err != nil {
			t.Error(err)
		}
	}
}

func ClientDataAccess(client *models.OauthClient) contract.OauthClientDataAccess {
	InitDatabase()
	clientStore := store.NewOauthClientStore(db)
	clientStoreError := clientStore.Migration()
	if clientStoreError != nil {
		return nil
	}
	err := clientStore.Set(client)
	if err != nil {
		return nil
	}
	return clientStore
}

func AccessTokenDataAccess() contract.OauthAccessTokenDataAccess {
	InitDatabase()
	accessTokenStore := store.NewOauthAccessTokenStore(db)
	accessTokenTokenError := accessTokenStore.Migration()
	if accessTokenTokenError != nil {
		return nil
	}
	return accessTokenStore
}
func RefreshTokenDataAccess() contract.OauthRefreshTokenDataAccess {
	InitDatabase()
	accessTokenStore := store.NewOauthRefreshTokenStore(db)
	accessTokenTokenError := accessTokenStore.Migration()
	if accessTokenTokenError != nil {
		return nil
	}
	return accessTokenStore
}

func TestRefreshToken(t *testing.T) {
	clientID := uuid.NewString()

	httpTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer httpTestServer.Close()
	e := httpexpect.New(t, httpTestServer.URL)
	// Set DataAccess
	manager.SetClientDataAccess(ClientDataAccess(&models.OauthClient{
		ID:                   clientID,
		UserID:               userID,
		Secret:               ClientSecretHashed(),
		Name:                 "Name",
		Provider:             "localhost",
		Redirect:             "http://localhost",
		PersonalAccessClient: false,
		PasswordClient:       false,
		Revoked:              false,
	}))
	manager.SetAccessTokenDataAccess(AccessTokenDataAccess())
	manager.SetRefreshTokenDataAccess(RefreshTokenDataAccess())
	manager.SetClientTokenCfg(&config.Config{
		IsGenerateRefresh: true,
		AccessTokenExp:    7200,
		RefreshTokenExp:   7200,
	})
	manager.MapAccessGenerate(&generates.JWTAccessGenerate{
		SignedKeyID:  "00000000",
		SignedKey:    []byte("00000000"),
		SignedMethod: jwt.SigningMethodHS512,
	})

	// Register Server
	srv = server.NewServer(&server.Config{
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
		ForcePKCE: true,
	}, manager)
	srv.SetClientInfoHandler(ClientInfoHandler)

	srv.UserAuthorizationHandler = func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		return userID, err
	}
	// Set Internal Error
	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		t.Log("OAuth 2.0 Error:", err.Error())
		return
	})

	// Set Response Error
	srv.SetResponseErrorHandler(func(re *errors.Response) {
		t.Log("Response Error:", re.Error)
	})

	// Set Allow Grant Type
	srv.SetAllowGetAccessRequest(false)
	srv.SetExtensionFieldsHandler(func(ti contract.AccessToken) (fieldsValue map[string]interface{}) {
		fieldsValue = map[string]interface{}{
			"extension": "param",
		}
		return
	})
	srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		return
	})
	srv.SetClientScopeHandler(func(tokenGenerateRequest *contract.TokenGenerateRequest) (allowed bool, err error) {
		allowed = true
		return
	})

	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, client contract.OauthClient, username, password string) (string, error) {
		return username, nil
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("client_id", clientID).
		WithFormField("client_secret", clientSecret).
		WithFormField("username", username).
		WithFormField("password", password).
		WithFormField("scope", "*").
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	validationRefreshToken(t, e, resObj.Value("refresh_token").String().Raw(), clientID)
}

func TestPassword(t *testing.T) {
	clientID := uuid.NewString()

	httpTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer httpTestServer.Close()
	e := httpexpect.New(t, httpTestServer.URL)
	// Set DataAccess
	manager.SetClientDataAccess(ClientDataAccess(&models.OauthClient{
		ID:                   clientID,
		UserID:               userID,
		Secret:               ClientSecretHashed(),
		Name:                 "Name",
		Provider:             "localhost",
		Redirect:             "http://localhost",
		PersonalAccessClient: false,
		PasswordClient:       false,
		Revoked:              false,
	}))
	manager.SetAccessTokenDataAccess(AccessTokenDataAccess())
	manager.SetRefreshTokenDataAccess(RefreshTokenDataAccess())
	manager.SetClientTokenCfg(&config.Config{
		IsGenerateRefresh: true,
		AccessTokenExp:    7200,
		RefreshTokenExp:   7200,
	})
	manager.MapAccessGenerate(&generates.JWTAccessGenerate{
		SignedKeyID:  "00000000",
		SignedKey:    []byte("00000000"),
		SignedMethod: jwt.SigningMethodHS512,
	})

	// Register Server
	srv = server.NewServer(&server.Config{
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
		ForcePKCE: true,
	}, manager)
	srv.SetClientInfoHandler(ClientInfoHandler)

	srv.UserAuthorizationHandler = func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		return userID, err
	}
	// Set Internal Error
	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		t.Log("OAuth 2.0 Error:", err.Error())
		return
	})

	// Set Response Error
	srv.SetResponseErrorHandler(func(re *errors.Response) {
		t.Log("Response Error:", re.Error)
	})

	// Set Allow Grant Type
	srv.SetAllowedGrantType(constant.PasswordCredentials)
	srv.SetAllowGetAccessRequest(false)
	srv.SetExtensionFieldsHandler(func(ti contract.AccessToken) (fieldsValue map[string]interface{}) {
		fieldsValue = map[string]interface{}{
			"extension": "param",
		}
		return
	})
	srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		return
	})
	srv.SetClientScopeHandler(func(tokenGenerateRequest *contract.TokenGenerateRequest) (allowed bool, err error) {
		allowed = true
		return
	})

	srv.SetPasswordAuthorizationHandler(func(ctx context.Context, client contract.OauthClient, username, password string) (string, error) {
		return username, nil
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "password").
		WithFormField("client_id", clientID).
		WithFormField("client_secret", string(clientSecret)).
		WithFormField("username", username).
		WithFormField("password", password).
		WithFormField("scope", "*").
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	validationAccessToken(t, resObj.Value("access_token").String().Raw(), clientID)
}

func TestClientCredentials(t *testing.T) {
	clientID := uuid.NewString()
	httpTestServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testServer(t, w, r)
	}))
	defer httpTestServer.Close()
	e := httpexpect.New(t, httpTestServer.URL)
	// Set DataAccess
	manager.SetClientDataAccess(ClientDataAccess(&models.OauthClient{
		ID:                   clientID,
		UserID:               userID,
		Secret:               ClientSecretHashed(),
		Name:                 "Name",
		Provider:             "localhost",
		Redirect:             "http://localhost",
		PersonalAccessClient: false,
		PasswordClient:       false,
		Revoked:              false,
	}))
	manager.SetAccessTokenDataAccess(AccessTokenDataAccess())
	manager.SetRefreshTokenDataAccess(RefreshTokenDataAccess())
	manager.SetClientTokenCfg(&config.Config{
		IsGenerateRefresh: true,
		AccessTokenExp:    7200,
		RefreshTokenExp:   7200,
	})
	manager.MapAccessGenerate(&generates.JWTAccessGenerate{
		SignedKeyID:  "00000000",
		SignedKey:    []byte("00000000"),
		SignedMethod: jwt.SigningMethodHS512,
	})

	// Register Server
	srv = server.NewDefaultServer(manager)
	srv.SetClientInfoHandler(ClientInfoHandler)

	// Set Internal Error
	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		t.Log("OAuth 2.0 Error:", err.Error())
		return
	})

	// Set Response Error
	srv.SetResponseErrorHandler(func(re *errors.Response) {
		t.Log("Response Error:", re.Error)
	})

	// Set Allow Grant Type
	srv.SetAllowedGrantType(constant.ClientCredentials)
	srv.SetAllowGetAccessRequest(false)
	srv.SetExtensionFieldsHandler(func(ti contract.AccessToken) (fieldsValue map[string]interface{}) {
		fieldsValue = map[string]interface{}{
			"extension": "param",
		}
		return
	})
	srv.SetAuthorizeScopeHandler(func(w http.ResponseWriter, r *http.Request) (scope string, err error) {
		return
	})
	srv.SetClientScopeHandler(func(tokenGenerateRequest *contract.TokenGenerateRequest) (allowed bool, err error) {
		allowed = true
		return
	})

	resObj := e.POST("/token").
		WithFormField("grant_type", "client_credentials").
		WithFormField("scope", "all").
		WithFormField("client_id", clientID).
		WithFormField("client_secret", string(clientSecret)).
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	validationAccessToken(t, resObj.Value("access_token").String().Raw(), clientID)
}

// validation access token
func validationAccessToken(t *testing.T, accessToken string, clientID string) {
	req := httptest.NewRequest("GET", "http://localhost", nil)

	req.Header.Set("Authorization", "Bearer "+accessToken)

	ti, err := srv.ValidationBearerToken(req)
	if err != nil {
		t.Error(err.Error())
		return
	}
	if ti.GetClientId() != clientID {
		t.Error("invalid access token")
	}
}

// validation refresh token
func validationRefreshToken(t *testing.T, e *httpexpect.Expect, refreshToken string, clientID string) {
	resObj := e.POST("/token").
		WithFormField("grant_type", "refresh_token").
		WithFormField("refresh_token", refreshToken).
		WithFormField("client_id", clientID).
		WithFormField("client_secret", clientSecret).
		WithFormField("scope", "*").
		Expect().
		Status(http.StatusOK).
		JSON().Object()

	validationAccessToken(t, resObj.Value("access_token").String().Raw(), clientID)
}

func ClientInfoHandler(r *http.Request) (client contract.OauthClient, err error) {
	clientId := r.Form.Get("client_id")
	if clientId == "" {
		return nil, errors.ErrInvalidClient
	}
	client, errClient := srv.Manager.GetClient(r.Context(), clientId)
	if errClient != nil {
		return nil, errClient
	}
	secret := r.Form.Get("client_secret")
	if !client.VerifyPassword(secret) {
		return nil, errors.ErrInvalidClient
	}
	return client, nil
}

func ClientSecretHashed() string {
	clientSecretHashed, _ := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	return string(clientSecretHashed)
}
