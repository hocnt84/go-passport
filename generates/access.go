package generates

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/hocnt84/go-passport/contract"
	"strconv"
	"strings"
)

// NewAccessGenerate create to generate the access token instance
func NewAccessGenerate() *AccessGenerate {
	return &AccessGenerate{}
}

// AccessGenerate generate the access token
type AccessGenerate struct {
}

func (ag *AccessGenerate) Decode(ctx context.Context, accessToken string) *jwt.StandardClaims {
	refreshToken := uuid.NewString()
	return &jwt.StandardClaims{
		Id: refreshToken,
	}
}

func (ag *AccessGenerate) RefreshToken(ctx context.Context, data *contract.GenerateBasic) (access string, err error) {
	refreshToken := uuid.NewString()
	return refreshToken, err
}

// Token based on the UUID generated token
func (ag *AccessGenerate) Token(ctx context.Context, data *contract.GenerateBasic) (string, error) {
	buf := bytes.NewBufferString(data.OauthClient.GetID())
	buf.WriteString(data.UserID)
	buf.WriteString(strconv.FormatInt(data.CreateAt.UnixNano(), 10))

	access := base64.URLEncoding.EncodeToString([]byte(uuid.NewMD5(uuid.Must(uuid.NewRandom()), buf.Bytes()).String()))
	access = strings.ToUpper(strings.TrimRight(access, "="))

	return access, nil
}
