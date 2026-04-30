package chat

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openimsdk/chat/pkg/botstruct"
	"github.com/openimsdk/chat/pkg/common/imapi"
	"github.com/openimsdk/chat/pkg/common/imwebhook"
	"github.com/openimsdk/chat/pkg/common/mctx"
	"github.com/openimsdk/chat/pkg/protocol/admin"
	"github.com/openimsdk/protocol/constant"
	"github.com/openimsdk/tools/errs"
	"github.com/openimsdk/tools/log"
	"github.com/openimsdk/tools/utils/datautil"
)

const (
	smartCustomerServiceModelURLConfigKey = "smart_customer_service_model_url"
	smartCustomerServiceModelName         = "qwen3"
	smartCustomerServiceModelTimeout      = 120 * time.Second
	openIMCallbackAfterSendSingleMsg      = "callbackAfterSendSingleMsgCommand"
)

type smartCustomerServiceModelReq struct {
	Model    string                             `json:"model"`
	Messages []smartCustomerServiceModelMessage `json:"messages"`
	Stream   bool                               `json:"stream"`
}

type smartCustomerServiceModelMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type smartCustomerServiceModelResp struct {
	Content string `json:"content"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (o *Api) handleSmartCustomerServiceSingleMsg(c context.Context, body string, key string) (bool, error) {
	var req imwebhook.CallbackAfterSendSingleMsgReq
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		return true, errs.ErrArgs.WrapMsg("parse after send single msg callback failed: " + err.Error())
	}
	if req.ContentType != constant.Text {
		return true, nil
	}

	conf, err := o.adminClient.GetClientConfig(c, &admin.GetClientConfigReq{})
	if err != nil {
		return true, err
	}
	if !isSmartCustomerServiceUser(req.RecvID, conf.Config[smartCustomerServiceConfigKey]) {
		return true, nil
	}

	modelURL := strings.TrimSpace(conf.Config[smartCustomerServiceModelURLConfigKey])
	if modelURL == "" {
		log.ZWarn(c, "smart customer service model url is empty", nil, "recvID", req.RecvID)
		return true, nil
	}

	var elem botstruct.TextElem
	if err := json.Unmarshal([]byte(req.Content), &elem); err != nil {
		return true, errs.ErrArgs.WrapMsg("parse text content failed: " + err.Error())
	}
	content := strings.TrimSpace(elem.Content)
	if content == "" {
		return true, nil
	}
	if key == "" {
		return true, errs.ErrArgs.WrapMsg("missing key in callback query")
	}

	go o.replySmartCustomerService(context.Background(), modelURL, req.RecvID, content, key)
	return true, nil
}

func isSmartCustomerServiceUser(userID string, rawUserIDs string) bool {
	rawUserIDs = strings.TrimSpace(rawUserIDs)
	if userID == "" || rawUserIDs == "" {
		return false
	}
	var userIDs []string
	if err := json.Unmarshal([]byte(rawUserIDs), &userIDs); err != nil {
		return false
	}
	return datautil.Contain(userID, userIDs...)
}

func (o *Api) replySmartCustomerService(ctx context.Context, modelURL, sendID, userContent, key string) {
	ctx, cancel := context.WithTimeout(ctx, smartCustomerServiceModelTimeout)
	defer cancel()

	reply, err := requestSmartCustomerServiceModel(ctx, modelURL, userContent)
	if err != nil {
		log.ZError(ctx, "request smart customer service model failed", err, "sendID", sendID)
		return
	}
	if strings.TrimSpace(reply) == "" {
		log.ZWarn(ctx, "smart customer service model returned empty content", nil, "sendID", sendID)
		return
	}

	imToken, err := o.imApiCaller.ImAdminTokenWithDefaultAdmin(ctx)
	if err != nil {
		log.ZError(ctx, "get im admin token failed", err, "sendID", sendID)
		return
	}
	ctx = mctx.WithApiToken(ctx, imToken)
	if err := o.imApiCaller.SendSimpleMsg(ctx, &imapi.SendSingleMsgReq{
		SendID:  sendID,
		Content: reply,
	}, key); err != nil {
		log.ZError(ctx, "send smart customer service reply failed", err, "sendID", sendID)
	}
}

func requestSmartCustomerServiceModel(ctx context.Context, modelURL, content string) (string, error) {
	reqBody := smartCustomerServiceModelReq{
		Model: smartCustomerServiceModelName,
		Messages: []smartCustomerServiceModelMessage{
			{Role: "user", Content: content},
		},
		Stream: false,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", errs.Wrap(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, modelURL, bytes.NewReader(body))
	if err != nil {
		return "", errs.Wrap(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", errs.Wrap(err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errs.Wrap(err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", errs.New("model http status error").WrapMsg("status " + resp.Status)
	}

	var modelResp smartCustomerServiceModelResp
	if err := json.Unmarshal(respBody, &modelResp); err != nil {
		return "", errs.WrapMsg(err, "parse model response failed")
	}
	if len(modelResp.Choices) > 0 && strings.TrimSpace(modelResp.Choices[0].Message.Content) != "" {
		return modelResp.Choices[0].Message.Content, nil
	}
	return modelResp.Content, nil
}
