package chat

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
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
	smartCustomerServiceModelURLConfigKey      = "smart_customer_service_model_url"
	smartCustomerServiceModelTimeoutConfigKey  = "smart_customer_service_model_timeout_seconds"
	smartCustomerServiceDefaultModelTimeout    = 60 * time.Second
	smartCustomerServiceMinModelTimeoutSeconds = 1
	smartCustomerServiceMaxModelTimeoutSeconds = 600
	smartCustomerServiceThinkingText           = "\u601d\u8003\u4e2d"
	smartCustomerServiceErrorText              = "\u667a\u80fd\u5ba2\u670d\u5f02\u5e38\uff0c\u8bf7\u8054\u7cfb\u5b98\u65b9\u8fd0\u8425"
	smartCustomerServiceLogTextLimit           = 4000
	openIMCallbackAfterSendSingleMsg           = "callbackAfterSendSingleMsgCommand"
)

type smartCustomerServiceModelReq struct {
	Question string `json:"question"`
}

type smartCustomerServiceMessageEx struct {
	HubMessageType string `json:"hubMessageType"`
}

type smartCustomerServiceModelResp struct {
	Answer  string `json:"answer"`
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
	log.ZWarn(c, "smart customer service callback reached", nil,
		"sendID", req.SendID,
		"recvID", req.RecvID,
		"contentType", req.ContentType,
		"keyEmpty", key == "",
	)

	conf, err := o.adminClient.GetClientConfig(c, &admin.GetClientConfigReq{})
	if err != nil {
		log.ZError(c, "smart customer service get config failed", err,
			"sendID", req.SendID,
			"recvID", req.RecvID,
		)
		return true, err
	}
	if !isSmartCustomerServiceUser(req.RecvID, conf.Config[smartCustomerServiceConfigKey]) {
		log.ZWarn(c, "smart customer service callback skipped non smart user", nil,
			"sendID", req.SendID,
			"recvID", req.RecvID,
			"configuredSmartUsers", conf.Config[smartCustomerServiceConfigKey],
		)
		return true, nil
	}
	if key == "" {
		return true, errs.ErrArgs.WrapMsg("missing key in callback query")
	}

	modelURL := strings.TrimSpace(conf.Config[smartCustomerServiceModelURLConfigKey])
	modelTimeout := smartCustomerServiceModelTimeout(conf.Config[smartCustomerServiceModelTimeoutConfigKey])
	content, canRequestModel := smartCustomerServiceModelContent(req)
	log.ZWarn(c, "smart customer service reply scheduled", nil,
		"sendID", req.RecvID,
		"userSendID", req.SendID,
		"modelURLConfigured", modelURL != "",
		"timeout", modelTimeout.String(),
		"canRequestModel", canRequestModel,
	)
	operationID := req.OperationID
	if operationID == "" {
		if value, ok := c.Value(constant.OperationID).(string); ok {
			operationID = value
		}
	}
	replyCtx := context.WithValue(context.Background(), constant.OperationID, operationID)
	go o.replySmartCustomerService(replyCtx, modelURL, req.RecvID, content, key, modelTimeout, canRequestModel)
	return true, nil
}

func smartCustomerServiceModelTimeout(rawTimeout string) time.Duration {
	timeoutSeconds, err := strconv.Atoi(strings.TrimSpace(rawTimeout))
	if err != nil {
		return smartCustomerServiceDefaultModelTimeout
	}
	if timeoutSeconds < smartCustomerServiceMinModelTimeoutSeconds {
		timeoutSeconds = smartCustomerServiceMinModelTimeoutSeconds
	}
	if timeoutSeconds > smartCustomerServiceMaxModelTimeoutSeconds {
		timeoutSeconds = smartCustomerServiceMaxModelTimeoutSeconds
	}
	return time.Duration(timeoutSeconds) * time.Second
}

func smartCustomerServiceModelContent(req imwebhook.CallbackAfterSendSingleMsgReq) (string, bool) {
	if req.ContentType != constant.Text {
		return "", false
	}
	var elem botstruct.TextElem
	if err := json.Unmarshal([]byte(req.Content), &elem); err != nil {
		return "", false
	}
	content := strings.TrimSpace(elem.Content)
	return content, content != ""
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

func (o *Api) replySmartCustomerService(ctx context.Context, modelURL, sendID, userContent, key string, modelTimeout time.Duration, canRequestModel bool) {
	ctx, cancel := context.WithTimeout(ctx, modelTimeout+10*time.Second)
	defer cancel()

	imToken, err := o.imApiCaller.ImAdminTokenWithDefaultAdmin(ctx)
	if err != nil {
		log.ZError(ctx, "get im admin token failed", err, "sendID", sendID)
		return
	}
	ctx = mctx.WithApiToken(ctx, imToken)

	if err := o.sendSmartCustomerServiceText(ctx, sendID, smartCustomerServiceThinkingText, key, smartCustomerServiceThinkingEx()); err != nil {
		log.ZError(ctx, "send smart customer service thinking failed", err, "sendID", sendID)
	} else {
		log.ZWarn(ctx, "send smart customer service thinking success", nil, "sendID", sendID)
	}

	if modelURL == "" || !canRequestModel {
		if modelURL == "" {
			log.ZWarn(ctx, "smart customer service model url is empty", nil, "sendID", sendID)
		}
		o.sendSmartCustomerServiceErrorAfterTimeout(ctx, sendID, key, modelTimeout)
		return
	}

	modelCtx, modelCancel := context.WithTimeout(ctx, modelTimeout)
	defer modelCancel()

	reply, err := requestSmartCustomerServiceModel(modelCtx, modelURL, userContent)
	if err != nil {
		log.ZError(ctx, "request smart customer service model failed", err, "sendID", sendID)
		_ = o.sendSmartCustomerServiceText(ctx, sendID, smartCustomerServiceErrorText, key, "")
		return
	}
	if strings.TrimSpace(reply) == "" {
		log.ZWarn(ctx, "smart customer service model returned empty content", nil, "sendID", sendID)
		_ = o.sendSmartCustomerServiceText(ctx, sendID, smartCustomerServiceErrorText, key, "")
		return
	}
	log.ZWarn(ctx, "smart customer service model reply ready", nil,
		"sendID", sendID,
		"replyLength", len(reply),
		"reply", limitSmartCustomerServiceLogText(reply),
	)

	if err := o.sendSmartCustomerServiceText(ctx, sendID, reply, key, ""); err != nil {
		log.ZError(ctx, "send smart customer service reply failed", err, "sendID", sendID)
	}
}

func (o *Api) sendSmartCustomerServiceErrorAfterTimeout(ctx context.Context, sendID, key string, modelTimeout time.Duration) {
	timer := time.NewTimer(modelTimeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return
	case <-timer.C:
		_ = o.sendSmartCustomerServiceText(ctx, sendID, smartCustomerServiceErrorText, key, "")
	}
}

func smartCustomerServiceThinkingEx() string {
	data, _ := json.Marshal(&smartCustomerServiceMessageEx{HubMessageType: "smart_customer_service_thinking"})
	return string(data)
}

func (o *Api) sendSmartCustomerServiceText(ctx context.Context, sendID, content, key, ex string) error {
	if err := o.imApiCaller.SendSimpleMsg(ctx, &imapi.SendSingleMsgReq{
		SendID:      sendID,
		Content:     content,
		ContentType: constant.Text,
		Ex:          ex,
	}, key); err != nil {
		return err
	}
	return nil
}

func requestSmartCustomerServiceModel(ctx context.Context, modelURL, content string) (string, error) {
	reqBody := smartCustomerServiceModelReq{
		Question: content,
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", errs.Wrap(err)
	}
	start := time.Now()
	log.ZWarn(ctx, "smart customer service model request start", nil,
		"modelURL", modelURL,
		"requestBody", limitSmartCustomerServiceLogText(string(body)),
	)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, modelURL, bytes.NewReader(body))
	if err != nil {
		log.ZError(ctx, "smart customer service model request build failed", err,
			"modelURL", modelURL,
			"elapsed", time.Since(start).String(),
		)
		return "", errs.Wrap(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.ZError(ctx, "smart customer service model http request failed", err,
			"modelURL", modelURL,
			"elapsed", time.Since(start).String(),
		)
		return "", errs.Wrap(err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.ZError(ctx, "smart customer service model response read failed", err,
			"modelURL", modelURL,
			"status", resp.Status,
			"elapsed", time.Since(start).String(),
		)
		return "", errs.Wrap(err)
	}
	log.ZWarn(ctx, "smart customer service model response received", nil,
		"modelURL", modelURL,
		"status", resp.Status,
		"statusCode", resp.StatusCode,
		"elapsed", time.Since(start).String(),
		"responseBody", limitSmartCustomerServiceLogText(string(respBody)),
	)
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		log.ZWarn(ctx, "smart customer service model http status error", nil,
			"modelURL", modelURL,
			"status", resp.Status,
			"elapsed", time.Since(start).String(),
			"responseBody", limitSmartCustomerServiceLogText(string(respBody)),
		)
		return "", errs.New("model http status error").WrapMsg("status " + resp.Status)
	}

	var modelResp smartCustomerServiceModelResp
	if err := json.Unmarshal(respBody, &modelResp); err != nil {
		log.ZError(ctx, "smart customer service model response parse failed", err,
			"modelURL", modelURL,
			"status", resp.Status,
			"elapsed", time.Since(start).String(),
			"responseBody", limitSmartCustomerServiceLogText(string(respBody)),
		)
		return "", errs.WrapMsg(err, "parse model response failed")
	}
	if len(modelResp.Choices) > 0 && strings.TrimSpace(modelResp.Choices[0].Message.Content) != "" {
		reply := modelResp.Choices[0].Message.Content
		log.ZWarn(ctx, "smart customer service model response parsed", nil,
			"modelURL", modelURL,
			"elapsed", time.Since(start).String(),
			"source", "choices[0].message.content",
			"replyLength", len(reply),
			"reply", limitSmartCustomerServiceLogText(reply),
		)
		return reply, nil
	}
	if strings.TrimSpace(modelResp.Content) != "" {
		log.ZWarn(ctx, "smart customer service model response parsed", nil,
			"modelURL", modelURL,
			"elapsed", time.Since(start).String(),
			"source", "content",
			"replyLength", len(modelResp.Content),
			"reply", limitSmartCustomerServiceLogText(modelResp.Content),
		)
		return modelResp.Content, nil
	}
	log.ZWarn(ctx, "smart customer service model response parsed", nil,
		"modelURL", modelURL,
		"elapsed", time.Since(start).String(),
		"source", "answer",
		"replyLength", len(modelResp.Answer),
		"reply", limitSmartCustomerServiceLogText(modelResp.Answer),
	)
	return modelResp.Answer, nil
}

func limitSmartCustomerServiceLogText(value string) string {
	if len(value) <= smartCustomerServiceLogTextLimit {
		return value
	}
	return value[:smartCustomerServiceLogTextLimit] + "...(truncated)"
}
