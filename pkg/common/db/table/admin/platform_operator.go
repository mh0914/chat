package admin

import (
	"context"
	"time"
)

type PlatformOperator struct {
	UserID         string    `bson:"user_id"`
	OperatorUserID string    `bson:"operator_user_id"`
	CreateTime     time.Time `bson:"create_time"`
}

func (PlatformOperator) TableName() string {
	return "platform_operators"
}

type PlatformOperatorInterface interface {
	Add(ctx context.Context, operators []*PlatformOperator) error
	Del(ctx context.Context, userIDs []string) error
	FindUserIDs(ctx context.Context, userIDs []string) ([]string, error)
}
