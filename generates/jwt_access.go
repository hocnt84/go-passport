package generates

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt"
	"github.com/hocnt84/go-passport/contract"
	"github.com/hocnt84/go-passport/errors"
	"strings"
	"time"
)

// JWTAccessClaims jwt claims
type JWTAccessClaims struct {
	jwt.StandardClaims
}

// Valid claims verification
func (a *JWTAccessClaims) Valid() error {
	if time.Unix(a.ExpiresAt, 0).Before(time.Now()) {
		return errors.ErrInvalidAccessToken
	}
	return nil
}

// NewJWTAccessGenerate create to generate the jwt access token instance
func NewJWTAccessGenerate(kid string, key []byte, method jwt.SigningMethod) *JWTAccessGenerate {
	return &JWTAccessGenerate{
		SignedKeyID:  kid,
		SignedKey:    key,
		SignedMethod: method,
	}
}

// JWTAccessGenerate generate the jwt access token
type JWTAccessGenerate struct {
	SignedKeyID  string
	SignedKey    []byte
	SignedMethod jwt.SigningMethod
}

func (a *JWTAccessGenerate) RefreshToken(ctx context.Context, data *contract.GenerateBasic) (access string, err error) {
	claims := &JWTAccessClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        data.OauthRefreshToken.GetID(),
			Audience:  data.OauthClient.GetID(),
			Subject:   data.UserID,
			ExpiresAt: data.OauthRefreshToken.GetExpiresAt().Unix(),
		},
	}
	token := jwt.NewWithClaims(a.SignedMethod, claims)
	if a.SignedKeyID != "" {
		token.Header["kid"] = a.SignedKeyID
	}
	var key interface{}
	if a.isEs() {
		v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", err
		}
		key = v
	} else if a.isRsOrPS() {
		v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", err
		}
		key = v
	} else if a.isHs() {
		key = a.SignedKey
	} else if a.isEd() {
		v, err := jwt.ParseEdPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", err
		}
		key = v
	} else {
		return "", errors.New("unsupported sign method")
	}

	refreshToken, refreshTokenError := token.SignedString(key)
	if refreshTokenError != nil {
		return "", refreshTokenError
	}

	return refreshToken, refreshTokenError
}

// Token based on the UUID generated token
func (a *JWTAccessGenerate) Token(ctx context.Context, data *contract.GenerateBasic) (string, error) {
	claims := &JWTAccessClaims{
		StandardClaims: jwt.StandardClaims{
			Id:        data.OauthAccessToken.GetID(),
			Audience:  data.OauthClient.GetID(),
			Subject:   data.UserID,
			ExpiresAt: data.OauthAccessToken.GetExpiresAt().Unix(),
		},
	}

	token := jwt.NewWithClaims(a.SignedMethod, claims)
	if a.SignedKeyID != "" {
		token.Header["kid"] = a.SignedKeyID
	}
	var key interface{}
	if a.isEs() {
		v, err := jwt.ParseECPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", err
		}
		key = v
	} else if a.isRsOrPS() {
		v, err := jwt.ParseRSAPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", err
		}
		key = v
	} else if a.isHs() {
		key = a.SignedKey
	} else if a.isEd() {
		v, err := jwt.ParseEdPrivateKeyFromPEM(a.SignedKey)
		if err != nil {
			return "", err
		}
		key = v
	} else {
		return "", errors.New("unsupported sign method")
	}

	access, err := token.SignedString(key)
	if err != nil {
		return "", err
	}

	return access, nil
}

func (a *JWTAccessGenerate) isEs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "ES")
}

func (a *JWTAccessGenerate) isRsOrPS() bool {
	isRs := strings.HasPrefix(a.SignedMethod.Alg(), "RS")
	isPs := strings.HasPrefix(a.SignedMethod.Alg(), "PS")
	return isRs || isPs
}

func (a *JWTAccessGenerate) isHs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "HS")
}

func (a *JWTAccessGenerate) isEd() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "Ed")
}

func (a *JWTAccessGenerate) Decode(ctx context.Context, accessToken string) *jwt.StandardClaims {
	token, err := jwt.ParseWithClaims(accessToken, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Check if the token's method is HMAC.
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		// Return the secret signing key (replace with your actual key)
		return a.SignedKey, nil
	})
	if err != nil || !token.Valid {
		return nil
	}
	claims, ok := token.Claims.(*jwt.StandardClaims)
	if !ok {
		return nil
	}
	return claims
}
