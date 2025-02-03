package store

import (
	"context"
	"github.com/hocnt84/go-passport/contract"
	"github.com/hocnt84/go-passport/models"
	"gorm.io/gorm"
	"time"
)

// NewOauthAccessTokenStore create one access token store
func NewOauthAccessTokenStore(db *gorm.DB) *OauthAccessTokenStore {
	return &OauthAccessTokenStore{db: db}
}

// OauthAccessTokenStore TokenStore token storage based on buntdb(https://github.com/tidwall/buntdb)
type OauthAccessTokenStore struct {
	db *gorm.DB
}

func (t *OauthAccessTokenStore) Migration() error {
	return t.db.AutoMigrate(&models.OauthAccessToken{})
}

func (t OauthAccessTokenStore) Create(ctx context.Context, info contract.OauthAccessToken) error {
	tx, ok := ctx.Value("tx").(*gorm.DB)
	if !ok {
		return t.db.Create(info).Error
	}
	return tx.Create(info).Error
}

func (t OauthAccessTokenStore) GetAccessTokenByRefreshToken(ctx context.Context, refreshTokenId string) (contract.OauthAccessToken, error) {
	refreshTokenQuery := t.db.Model(&models.OauthRefreshToken{}).Where("revoked = ? AND expires_at > ? AND id = ?", false, time.Now().UTC(), refreshTokenId).Select("access_token_id")
	var accessToken = &models.OauthAccessToken{}
	tx := t.db.Where("id = (?)", refreshTokenQuery).First(accessToken)
	if err := tx.Error; err != nil {
		return nil, err
	}
	return accessToken, nil
}

func (t OauthAccessTokenStore) RemoveByAccessTokenId(ctx context.Context, accessTokenId string) error {
	return t.db.Where(&models.OauthAccessToken{
		ID: accessTokenId,
	}).Delete(&models.OauthAccessToken{}).Error
}

func (t OauthAccessTokenStore) GetByAccess(ctx context.Context, access string) (contract.OauthAccessToken, error) {
	var accessToken = &models.OauthAccessToken{
		ID: access,
	}
	tx := t.db.First(accessToken)
	if err := tx.Error; err != nil {
		return nil, err
	}
	return accessToken, nil
}
