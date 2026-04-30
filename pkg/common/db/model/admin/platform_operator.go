package admin

import (
	"context"

	"github.com/openimsdk/chat/pkg/common/db/table/admin"
	"github.com/openimsdk/tools/db/mongoutil"
	"github.com/openimsdk/tools/errs"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

func NewPlatformOperator(db *mongo.Database) (admin.PlatformOperatorInterface, error) {
	coll := db.Collection("platform_operator")
	_, err := coll.Indexes().CreateOne(context.Background(), mongo.IndexModel{
		Keys: bson.D{
			{Key: "user_id", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return nil, errs.Wrap(err)
	}
	return &PlatformOperator{coll: coll}, nil
}

type PlatformOperator struct {
	coll *mongo.Collection
}

func (o *PlatformOperator) Add(ctx context.Context, operators []*admin.PlatformOperator) error {
	return mongoutil.InsertMany(ctx, o.coll, operators)
}

func (o *PlatformOperator) Del(ctx context.Context, userIDs []string) error {
	if len(userIDs) == 0 {
		return nil
	}
	return mongoutil.DeleteMany(ctx, o.coll, bson.M{"user_id": bson.M{"$in": userIDs}})
}

func (o *PlatformOperator) FindUserIDs(ctx context.Context, userIDs []string) ([]string, error) {
	filter := bson.M{}
	if len(userIDs) > 0 {
		filter["user_id"] = bson.M{"$in": userIDs}
	}
	return mongoutil.Find[string](
		ctx,
		o.coll,
		filter,
		options.Find().SetProjection(bson.M{"_id": 0, "user_id": 1}),
	)
}
