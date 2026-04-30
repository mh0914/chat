package admin

import (
	"context"
	"time"

	"github.com/openimsdk/chat/pkg/common/constant"
	admindb "github.com/openimsdk/chat/pkg/common/db/table/admin"
	"github.com/openimsdk/chat/pkg/common/mctx"
	adminpb "github.com/openimsdk/chat/pkg/protocol/admin"
	chatpb "github.com/openimsdk/chat/pkg/protocol/chat"
	"github.com/openimsdk/protocol/sdkws"
	"github.com/openimsdk/tools/mcontext"
	"github.com/openimsdk/tools/utils/datautil"
)

const operatorFriendBatchSize int32 = 500

func (o *adminServer) SetPlatformOperator(ctx context.Context, req *adminpb.SetPlatformOperatorReq) (*adminpb.SetPlatformOperatorResp, error) {
	if _, err := mctx.CheckAdmin(ctx); err != nil {
		return nil, err
	}

	if req.IsPlatformOperator {
		if _, err := o.Chat.GetUserFullInfo(ctx, req.UserID); err != nil {
			return nil, err
		}
		operatorIDs, err := o.Database.FindPlatformOperator(ctx, []string{req.UserID})
		if err != nil {
			return nil, err
		}
		if len(operatorIDs) == 0 {
			if err := o.Database.AddPlatformOperator(ctx, []*admindb.PlatformOperator{
				{
					UserID:         req.UserID,
					OperatorUserID: mcontext.GetOpUserID(ctx),
					CreateTime:     time.Now(),
				},
			}); err != nil {
				return nil, err
			}
		}

		defaultFriendIDs, err := o.Database.FindDefaultFriend(ctx, []string{req.UserID})
		if err != nil {
			return nil, err
		}
		if len(defaultFriendIDs) == 0 {
			if err := o.Database.AddDefaultFriend(ctx, []*admindb.RegisterAddFriend{
				{
					UserID:     req.UserID,
					CreateTime: time.Now(),
				},
			}); err != nil {
				return nil, err
			}
		}

		friendIDs, err := o.listAllUserIDs(ctx, req.UserID)
		if err != nil {
			return nil, err
		}
		imToken, err := o.IM.ImAdminTokenWithDefaultAdmin(ctx)
		if err != nil {
			return nil, err
		}
		apiCtx := mctx.WithApiToken(ctx, imToken)
		if err := o.IM.ImportFriend(apiCtx, req.UserID, friendIDs); err != nil {
			return nil, err
		}
	} else {
		if err := o.Database.DelPlatformOperator(ctx, []string{req.UserID}); err != nil {
			return nil, err
		}
		if err := o.Database.DelDefaultFriend(ctx, []string{req.UserID}); err != nil {
			return nil, err
		}
	}

	return &adminpb.SetPlatformOperatorResp{}, nil
}

func (o *adminServer) FindPlatformOperator(ctx context.Context, req *adminpb.FindPlatformOperatorReq) (*adminpb.FindPlatformOperatorResp, error) {
	userIDs, err := o.Database.FindPlatformOperator(ctx, req.UserIDs)
	if err != nil {
		return nil, err
	}
	return &adminpb.FindPlatformOperatorResp{UserIDs: userIDs}, nil
}

func (o *adminServer) listAllUserIDs(ctx context.Context, excludeUserID string) ([]string, error) {
	pageNumber := int32(1)
	userIDs := make([]string, 0, operatorFriendBatchSize)

	for {
		resp, err := o.Chat.SearchUserFullInfo(ctx, &chatpb.SearchUserFullInfoReq{
			Normal: constant.FinDAllUser,
			Pagination: &sdkws.RequestPagination{
				PageNumber: pageNumber,
				ShowNumber: operatorFriendBatchSize,
			},
		})
		if err != nil {
			return nil, err
		}
		if len(resp.Users) == 0 {
			break
		}

		for _, user := range resp.Users {
			if user.GetUserID() == "" || user.GetUserID() == excludeUserID {
				continue
			}
			userIDs = append(userIDs, user.GetUserID())
		}

		if int32(len(resp.Users)) < operatorFriendBatchSize {
			break
		}
		pageNumber++
	}

	return datautil.Distinct(userIDs), nil
}
