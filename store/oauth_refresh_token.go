package store

import (
	"context"
	"github.com/hocnt84/go-passport/contract"
	"github.com/hocnt84/go-passport/models"
	"gorm.io/gorm"
	"time"
)

func NewOauthRefreshTokenStore(db *gorm.DB) *OauthRefreshTokenStore {
	return &OauthRefreshTokenStore{
		db: db,
	}
}

// OauthRefreshTokenStore information store
type OauthRefreshTokenStore struct {
	db *gorm.DB
}

func (o *OauthRefreshTokenStore) Migration() error {
	return o.db.AutoMigrate(&models.OauthRefreshToken{})
}

func (o *OauthRefreshTokenStore) Create(ctx context.Context, info contract.OauthRefreshToken) error {
	return o.db.Create(info).Error
}

func (o *OauthRefreshTokenStore) GetAccessToken(ctx context.Context, refreshTokenId string) (contract.OauthAccessToken, error) {
	refreshTokenQuery := o.db.Model(&models.OauthRefreshToken{}).Where("revoked = ? AND expires_at > ? AND id = ?", false, time.Now().UTC(), refreshTokenId).Select("access_token_id")
	var accessToken = &models.OauthAccessToken{}
	tx := o.db.Where("id = (?)", refreshTokenQuery).First(accessToken)
	if err := tx.Error; err != nil {
		return nil, err
	}
	return accessToken, nil
}

func (o *OauthRefreshTokenStore) RemoveByRefreshTokenId(ctx context.Context, refreshTokenId string) error {
	return o.db.Where(&models.OauthRefreshToken{
		ID: refreshTokenId,
	}).Delete(&models.OauthRefreshToken{}).Error
}

func (o *OauthRefreshTokenStore) RemoveByAccessTokenId(ctx context.Context, accessTokenId string) error {
	return o.db.Where(&models.OauthRefreshToken{
		AccessTokenId: accessTokenId,
	}).Delete(&models.OauthRefreshToken{}).Error
}
