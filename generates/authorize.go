package generates

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/google/uuid"
	"github.com/hocnt84/go-passport/contract"
	"strings"
)

// NewAuthorizeGenerate create to generate the authorize code instance
func NewAuthorizeGenerate() *AuthorizeGenerate {
	return &AuthorizeGenerate{}
}

// AuthorizeGenerate generate the authorize code
type AuthorizeGenerate struct{}

// Token based on the UUID generated token
func (ag *AuthorizeGenerate) Token(ctx context.Context, data *contract.GenerateBasic) (string, error) {
	buf := bytes.NewBufferString(data.OauthClient.GetID())
	buf.WriteString(data.UserID)
	token := uuid.NewMD5(uuid.Must(uuid.NewRandom()), buf.Bytes())
	code := base64.URLEncoding.EncodeToString([]byte(token.String()))
	code = strings.ToUpper(strings.TrimRight(code, "="))

	return code, nil
}
