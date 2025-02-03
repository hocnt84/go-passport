package store

import (
	"context"
	"github.com/hocnt84/go-passport/contract"
	"github.com/hocnt84/go-passport/models"
	"gorm.io/gorm"
)

// NewOauthClientStore NewClientStore create client store
func NewOauthClientStore(db *gorm.DB, tx string) *OauthClientStore {
	return &OauthClientStore{
		db: db,
		tx: tx,
	}
}

// OauthClientStore ClientStore client information store
type OauthClientStore struct {
	db *gorm.DB
	tx string
}

func (o *OauthClientStore) GetByID(ctx context.Context, id string) (contract.OauthClient, error) {
	var oauthClient = models.OauthClient{
		ID: id,
	}
	tx := o.db.First(&oauthClient)
	if tx.Error != nil {
		return nil, tx.Error
	}
	return &oauthClient, nil
}

// Set client information
func (o *OauthClientStore) Set(cli contract.OauthClient) (err error) {
	return o.db.Create(cli).Error
}

func (o *OauthClientStore) Migration() error {
	return o.db.AutoMigrate(&models.OauthClient{})
}
