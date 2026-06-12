package chat

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openimsdk/chat/pkg/common/apistruct"
	"github.com/openimsdk/chat/pkg/common/constant"
	"github.com/openimsdk/chat/pkg/common/mctx"
	"github.com/openimsdk/chat/pkg/protocol/admin"
	chatpb "github.com/openimsdk/chat/pkg/protocol/chat"
	protocolconst "github.com/openimsdk/protocol/constant"
	"github.com/openimsdk/protocol/sdkws"
	"github.com/openimsdk/protocol/wrapperspb"
	"github.com/openimsdk/tools/apiresp"
	"github.com/openimsdk/tools/errs"
	"github.com/openimsdk/tools/log"
	"github.com/openimsdk/tools/mcontext"
	"github.com/openimsdk/tools/utils/datautil"
	"github.com/openimsdk/tools/utils/idutil"
)

const (
	defaultSSOScope          = "openid"
	defaultSSOTicketTTL      = 2 * time.Minute
	defaultSSORequestTimeout = 15 * time.Second
)

var ssoTicketStore = newSSOTicketStore()

type ssoConfig struct {
	Enabled            bool
	PublicOrigin       string
	AuthorizeURL       string
	TokenURL           string
	UserInfoURL        string
	APIBaseURL         string
	ClientID           string
	ClientSecret       string
	RedirectURI        string
	Scope              string
	UserIDPrefix       string
	InsecureSkipVerify bool
}

type ssoLoginTicket struct {
	IMToken   string
	ChatToken string
	UserID    string
	ExpiresAt time.Time
}

type ssoTickets struct {
	lock    sync.Mutex
	tickets map[string]ssoLoginTicket
}

func newSSOTicketStore() *ssoTickets {
	return &ssoTickets{tickets: make(map[string]ssoLoginTicket)}
}

func (s *ssoTickets) put(ticket ssoLoginTicket) (string, error) {
	id, err := randomURLToken(32)
	if err != nil {
		return "", err
	}
	s.lock.Lock()
	defer s.lock.Unlock()
	s.cleanupLocked(time.Now())
	s.tickets[id] = ticket
	return id, nil
}

func (s *ssoTickets) consume(id string) (ssoLoginTicket, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	now := time.Now()
	s.cleanupLocked(now)
	ticket, ok := s.tickets[id]
	if !ok || ticket.ExpiresAt.Before(now) {
		delete(s.tickets, id)
		return ssoLoginTicket{}, false
	}
	delete(s.tickets, id)
	return ticket, true
}

func (s *ssoTickets) cleanupLocked(now time.Time) {
	for id, ticket := range s.tickets {
		if ticket.ExpiresAt.Before(now) {
			delete(s.tickets, id)
		}
	}
}

type ssoExchangeTicketReq struct {
	Ticket string `json:"ticket"`
}

type ssoSubject struct {
	ExternalID string
	Account    string
	UserID     string
	Nickname   string
	FaceURL    string
	Email      string
	AreaCode   string
	Phone      string
	SubjectEx  string
}

func (o *Api) SSOAuthorize(c *gin.Context) {
	cfg, err := loadSSOConfig(c.Request)
	if err != nil {
		ssoTextError(c, http.StatusServiceUnavailable, err)
		return
	}
	redirectSSOAuthorize(c, cfg)
}

func redirectSSOAuthorize(c *gin.Context, cfg ssoConfig) {
	state, err := randomURLToken(24)
	if err != nil {
		ssoTextError(c, http.StatusInternalServerError, err)
		return
	}
	setSSOStateCookie(c, cfg, state)

	u, err := url.Parse(cfg.AuthorizeURL)
	if err != nil {
		ssoTextError(c, http.StatusInternalServerError, errs.WrapMsg(err, "invalid oauth authorize url"))
		return
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	if cfg.Scope != "" {
		q.Set("scope", cfg.Scope)
	}
	q.Set("state", state)
	q.Set("redirect_uri", cfg.RedirectURI)
	u.RawQuery = q.Encode()
	log.ZInfo(c, "sso authorize redirect", "url", u.String())
	c.Redirect(http.StatusFound, u.String())
}

func (o *Api) SSOCallback(c *gin.Context) {
	ensureSSOOperationID(c)
	cfg, err := loadSSOConfig(c.Request)
	if err != nil {
		ssoTextError(c, http.StatusServiceUnavailable, err)
		return
	}
	if !hasSSOCallbackParams(c) {
		redirectSSOAuthorize(c, cfg)
		return
	}
	if err := validateSSOState(c); err != nil {
		ssoTextError(c, http.StatusBadRequest, err)
		return
	}
	if oauthErr := strings.TrimSpace(c.Query("error")); oauthErr != "" {
		description := strings.TrimSpace(c.Query("error_description"))
		message := "oauth authorization failed: " + oauthErr
		if description != "" {
			message += " (" + description + ")"
		}
		ssoTextError(c, http.StatusBadRequest, errs.ErrArgs.WrapMsg(message))
		return
	}
	code := strings.TrimSpace(c.Query("code"))
	if code == "" {
		ssoTextError(c, http.StatusBadRequest, errs.ErrArgs.WrapMsg("missing oauth code"))
		return
	}
	accessToken, err := exchangeSSOAccessToken(c, cfg, code)
	if err != nil {
		ssoTextError(c, http.StatusBadGateway, err)
		return
	}
	rawUser, err := fetchSSOUserInfo(c, cfg, accessToken)
	if err != nil {
		ssoTextError(c, http.StatusBadGateway, err)
		return
	}
	subject, err := normalizeSSOSubject(cfg, rawUser)
	if err != nil {
		ssoTextError(c, http.StatusBadGateway, err)
		return
	}
	loginTicket, err := o.ensureSSOUserAndCreateTicket(c, cfg, subject)
	if err != nil {
		ssoTextError(c, http.StatusInternalServerError, err)
		return
	}
	ticketID, err := ssoTicketStore.put(loginTicket)
	if err != nil {
		ssoTextError(c, http.StatusInternalServerError, err)
		return
	}
	redirectURL := strings.TrimRight(cfg.PublicOrigin, "/") + "/#/sso/login?ticket=" + url.QueryEscape(ticketID)
	c.Redirect(http.StatusFound, redirectURL)
}

func hasSSOCallbackParams(c *gin.Context) bool {
	return strings.TrimSpace(c.Query("code")) != "" ||
		strings.TrimSpace(c.Query("state")) != "" ||
		strings.TrimSpace(c.Query("error")) != "" ||
		strings.TrimSpace(c.Query("error_description")) != ""
}

func ensureSSOOperationID(c *gin.Context) {
	if operationID := mcontext.GetOperationID(c); operationID != "" {
		return
	}
	operationID := strings.TrimSpace(c.GetHeader(protocolconst.OperationID))
	if operationID == "" {
		operationID = "SSO" + idutil.OperationIDGenerator()
	}
	c.Set(protocolconst.OperationID, operationID)
	c.Request = c.Request.WithContext(mcontext.SetOperationID(c.Request.Context(), operationID))
}

func (o *Api) SSOExchangeTicket(c *gin.Context) {
	var req ssoExchangeTicketReq
	if err := c.ShouldBindJSON(&req); err != nil {
		apiresp.GinError(c, err)
		return
	}
	ticket, ok := ssoTicketStore.consume(strings.TrimSpace(req.Ticket))
	if !ok {
		apiresp.GinError(c, errs.ErrArgs.WrapMsg("sso ticket expired or invalid"))
		return
	}
	apiresp.GinSuccess(c, &apistruct.LoginResp{
		ImToken:   ticket.IMToken,
		ChatToken: ticket.ChatToken,
		UserID:    ticket.UserID,
	})
}

func (o *Api) SSOLogout(c *gin.Context) {
	cfg, err := loadSSOConfig(c.Request)
	if err == nil {
		if subject, ok := logoutSSOSubjectFromRequest(c, cfg); ok {
			if err := o.forceLogoutSSOUser(c, subject.Account); err != nil {
				log.ZWarn(c, "sso force logout failed", err, "account", subject.Account)
			}
		}
	}
	if c.Request.Method == http.MethodGet {
		publicOrigin := ""
		if err == nil {
			publicOrigin = strings.TrimRight(cfg.PublicOrigin, "/")
		}
		if publicOrigin == "" {
			publicOrigin = "/"
		}
		c.Redirect(http.StatusFound, publicOrigin+"/#/login?ssoLogout=1")
		return
	}
	apiresp.GinSuccess(c, nil)
}

func (o *Api) ensureSSOUserAndCreateTicket(c *gin.Context, cfg ssoConfig, subject ssoSubject) (ssoLoginTicket, error) {
	rpcCtx := o.WithAdminUser(c)
	checkResp, err := o.chatClient.CheckUserExist(rpcCtx, &chatpb.CheckUserExistReq{
		User: &chatpb.RegisterUserInfo{Account: subject.Account},
	})
	if err != nil {
		return ssoLoginTicket{}, err
	}
	userID := subject.UserID
	if checkResp != nil && checkResp.IsRegistered {
		userID = checkResp.Userid
		if err := o.updateSSOUserInfo(c, userID, subject); err != nil {
			log.ZWarn(c, "update sso user info failed", err, "userID", userID)
		}
	} else {
		if err := o.registerSSOUser(c, rpcCtx, cfg, subject); err != nil {
			return ssoLoginTicket{}, err
		}
	}

	chatToken, err := o.adminClient.CreateToken(rpcCtx, &admin.CreateTokenReq{
		UserID:   userID,
		UserType: constant.NormalUser,
	})
	if err != nil {
		return ssoLoginTicket{}, err
	}
	imAdminToken, err := o.imApiCaller.ImAdminTokenWithDefaultAdmin(c)
	if err != nil {
		return ssoLoginTicket{}, err
	}
	apiCtx := mctx.WithApiToken(c, imAdminToken)
	imToken, err := o.imApiCaller.GetUserToken(apiCtx, userID, 5)
	if err != nil {
		return ssoLoginTicket{}, err
	}
	return ssoLoginTicket{
		IMToken:   imToken,
		ChatToken: chatToken.Token,
		UserID:    userID,
		ExpiresAt: time.Now().Add(defaultSSOTicketTTL),
	}, nil
}

func (o *Api) registerSSOUser(c *gin.Context, rpcCtx context.Context, cfg ssoConfig, subject ssoSubject) error {
	respRegisterUser, err := o.chatClient.RegisterUser(rpcCtx, &chatpb.RegisterUserReq{
		Ip:       clientIPOrEmpty(o, c),
		Platform: 5,
		User: &chatpb.RegisterUserInfo{
			UserID:      subject.UserID,
			Account:     subject.Account,
			Nickname:    subject.Nickname,
			FaceURL:     subject.FaceURL,
			Email:       subject.Email,
			AreaCode:    subject.AreaCode,
			PhoneNumber: subject.Phone,
		},
	})
	if err != nil {
		return err
	}
	imToken, err := o.imApiCaller.ImAdminTokenWithDefaultAdmin(c)
	if err != nil {
		return err
	}
	apiCtx := mctx.WithApiToken(c, imToken)
	userInfo := &sdkws.UserInfo{
		UserID:     respRegisterUser.UserID,
		Nickname:   subject.Nickname,
		FaceURL:    subject.FaceURL,
		Ex:         subject.SubjectEx,
		CreateTime: time.Now().UnixMilli(),
	}
	if err := o.imApiCaller.RegisterUser(apiCtx, []*sdkws.UserInfo{userInfo}); err != nil {
		return err
	}
	if resp, err := o.adminClient.FindDefaultFriend(rpcCtx, &admin.FindDefaultFriendReq{}); err == nil {
		_ = o.imApiCaller.ImportFriend(apiCtx, respRegisterUser.UserID, resp.UserIDs)
	}
	if resp, err := o.adminClient.FindDefaultGroup(rpcCtx, &admin.FindDefaultGroupReq{}); err == nil {
		_ = o.imApiCaller.InviteToGroup(apiCtx, respRegisterUser.UserID, resp.GroupIDs)
	}
	_ = cfg
	return nil
}

func (o *Api) updateSSOUserInfo(c *gin.Context, userID string, subject ssoSubject) error {
	req := &chatpb.UpdateUserInfoReq{UserID: userID}
	if subject.Nickname != "" {
		req.Nickname = &wrapperspb.StringValue{Value: subject.Nickname}
	}
	if subject.FaceURL != "" {
		req.FaceURL = &wrapperspb.StringValue{Value: subject.FaceURL}
	}
	if subject.Email != "" {
		req.Email = &wrapperspb.StringValue{Value: subject.Email}
	}
	if subject.Phone != "" || subject.AreaCode != "" {
		req.AreaCode = &wrapperspb.StringValue{Value: subject.AreaCode}
		req.PhoneNumber = &wrapperspb.StringValue{Value: subject.Phone}
	}
	resp, err := o.chatClient.UpdateUserInfo(o.WithAdminUser(c), req)
	if err != nil {
		log.ZWarn(c, "update sso chat user info failed; retrying nickname and avatar only", err, "userID", userID)
		req = &chatpb.UpdateUserInfoReq{UserID: userID}
		if subject.Nickname != "" {
			req.Nickname = &wrapperspb.StringValue{Value: subject.Nickname}
		}
		if subject.FaceURL != "" {
			req.FaceURL = &wrapperspb.StringValue{Value: subject.FaceURL}
		}
		resp, err = o.chatClient.UpdateUserInfo(o.WithAdminUser(c), req)
		if err != nil {
			return err
		}
	}
	nickname := subject.Nickname
	if nickname == "" {
		nickname = resp.NickName
	}
	faceURL := subject.FaceURL
	if faceURL == "" {
		faceURL = resp.FaceUrl
	}
	imToken, err := o.imApiCaller.ImAdminTokenWithDefaultAdmin(c)
	if err != nil {
		return err
	}
	if subject.SubjectEx != "" {
		return o.imApiCaller.UpdateUserInfoEx(mctx.WithApiToken(c, imToken), userID, nickname, faceURL, subject.SubjectEx)
	}
	return o.imApiCaller.UpdateUserInfo(mctx.WithApiToken(c, imToken), userID, nickname, faceURL)
}

func (o *Api) forceLogoutSSOUser(c *gin.Context, account string) error {
	checkResp, err := o.chatClient.CheckUserExist(o.WithAdminUser(c), &chatpb.CheckUserExistReq{
		User: &chatpb.RegisterUserInfo{Account: account},
	})
	if err != nil || checkResp == nil || !checkResp.IsRegistered {
		return err
	}
	_, _ = o.adminClient.InvalidateToken(o.WithAdminUser(c), &admin.InvalidateTokenReq{UserID: checkResp.Userid})
	imToken, err := o.imApiCaller.ImAdminTokenWithDefaultAdmin(c)
	if err != nil {
		return err
	}
	return o.imApiCaller.ForceOffLine(mctx.WithApiToken(c, imToken), checkResp.Userid)
}

func loadSSOConfig(r *http.Request) (ssoConfig, error) {
	publicOrigin := firstNonEmpty(os.Getenv("HUBMESSAGE_PUBLIC_ORIGIN"), requestOrigin(r))
	cfg := ssoConfig{
		Enabled:            envBool("HUBMESSAGE_SSO_ENABLED", false),
		PublicOrigin:       strings.TrimRight(publicOrigin, "/"),
		AuthorizeURL:       strings.TrimSpace(os.Getenv("HUBMESSAGE_SSO_AUTHORIZE_URL")),
		TokenURL:           strings.TrimSpace(os.Getenv("HUBMESSAGE_SSO_TOKEN_URL")),
		UserInfoURL:        strings.TrimSpace(os.Getenv("HUBMESSAGE_SSO_USERINFO_URL")),
		APIBaseURL:         strings.TrimRight(strings.TrimSpace(os.Getenv("HUBMESSAGE_SSO_API_BASE_URL")), "/"),
		ClientID:           strings.TrimSpace(os.Getenv("HUBMESSAGE_SSO_CLIENT_ID")),
		ClientSecret:       strings.TrimSpace(os.Getenv("HUBMESSAGE_SSO_CLIENT_SECRET")),
		RedirectURI:        strings.TrimSpace(os.Getenv("HUBMESSAGE_SSO_REDIRECT_URI")),
		Scope:              firstNonEmpty(os.Getenv("HUBMESSAGE_SSO_SCOPE"), defaultSSOScope),
		UserIDPrefix:       firstNonEmpty(os.Getenv("HUBMESSAGE_SSO_USER_ID_PREFIX"), "sso"),
		InsecureSkipVerify: envBool("HUBMESSAGE_SSO_INSECURE_SKIP_VERIFY", false),
	}
	if cfg.RedirectURI == "" && cfg.PublicOrigin != "" {
		cfg.RedirectURI = cfg.PublicOrigin + "/chat/sso/oauth2/callback"
	}
	if !cfg.Enabled {
		return cfg, errs.ErrNoPermission.WrapMsg("sso is disabled")
	}
	if cfg.AuthorizeURL == "" || cfg.TokenURL == "" || cfg.UserInfoURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.RedirectURI == "" {
		return cfg, errs.ErrArgs.WrapMsg("sso config is incomplete")
	}
	return cfg, nil
}

func exchangeSSOAccessToken(ctx context.Context, cfg ssoConfig, code string) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	resp, err := postBasicFormMap(ctx, cfg, cfg.TokenURL, form)
	if err != nil {
		return "", err
	}
	token := extractStringFromMap(resp, "access_token", "accessToken", "token")
	if token == "" {
		return "", errs.ErrInternalServer.WrapMsg("oauth token response missing access_token")
	}
	return token, nil
}

func fetchSSOUserInfo(ctx context.Context, cfg ssoConfig, accessToken string) (map[string]any, error) {
	resp, err := getJSONMap(ctx, cfg, cfg.UserInfoURL, accessToken)
	if err != nil {
		resp, err = postJSONMap(ctx, cfg, cfg.UserInfoURL, nil, accessToken)
	}
	if err != nil {
		return nil, err
	}
	resp = map[string]any{"oauthUserInfo": resp}
	if cfg.APIBaseURL != "" {
		if detail, err := fetchTDSPSubjectInfo(ctx, cfg, accessToken); err == nil && len(detail) > 0 {
			resp = mergeJSONMaps(resp, detail)
		}
	}
	return resp, nil
}

func fetchTDSPSubjectInfo(ctx context.Context, cfg ssoConfig, accessToken string) (map[string]any, error) {
	typeResp, err := postJSONMap(ctx, cfg, cfg.APIBaseURL+"/api/tdsp/v1/account/auth/GetUserType", nil, accessToken)
	if err != nil {
		return nil, err
	}
	userType := int(extractNumberFromMap(typeResp, "UserType", "userType"))
	result := map[string]any{
		"tdspSubjectType": typeResp,
	}
	endpoint := ""
	detailKey := ""
	switch userType {
	case 1:
		endpoint = "/api/tdsp/v1/account/auth/GetPersonInfo"
		detailKey = "tdspPersonInfo"
	case 2:
		endpoint = "/api/tdsp/v1/account/auth/GetEnterpriseInfo"
		detailKey = "tdspEnterpriseInfo"
	case 3:
		endpoint = "/api/tdsp/v1/account/auth/GetOperatorInfo"
		detailKey = "tdspOperatorInfo"
	default:
		return result, nil
	}
	detail, err := postJSONMap(ctx, cfg, cfg.APIBaseURL+endpoint, nil, accessToken)
	if err != nil {
		return result, nil
	}
	result[detailKey] = detail
	return result, nil
}

func normalizeSSOSubject(cfg ssoConfig, raw map[string]any) (ssoSubject, error) {
	externalID := extractStringFromMap(raw,
		"identityId", "operatorIdentityID", "enterpriseIdentityID", "personIdentityID", "sub", "userID", "userId", "id", "account",
	)
	if externalID == "" {
		return ssoSubject{}, errs.ErrInternalServer.WrapMsg("sso user info missing identity id")
	}
	account := buildSSOAccount(cfg.UserIDPrefix, externalID)
	nickname := extractStringFromMap(raw,
		"displayname", "displayName", "fullName", "operator", "enterpriseName", "nickname", "name", "usercode", "userCode", "userName", "username", "enterpriseIdentityName",
	)
	if nickname == "" {
		nickname = account
	}
	subject := ssoSubject{
		ExternalID: externalID,
		Account:    account,
		UserID:     account,
		Nickname:   nickname,
		FaceURL:    extractStringFromMap(raw, "faceURL", "avatar", "avatarUrl", "photo", "headImage"),
		Email:      extractValidEmailFromMap(raw, "email", "mail", "emailAddress"),
		SubjectEx:  buildSSOSubjectEx(raw, externalID),
	}
	subject.AreaCode = extractAreaCodeFromMap(raw, "areaCode", "phoneAreaCode", "mobileAreaCode")
	subject.Phone = extractPhoneFromMap(raw, "phoneNumber", "phone", "mobile", "mobilePhone", "telephone")
	if subject.AreaCode == "" || subject.Phone == "" {
		subject.AreaCode = ""
		subject.Phone = ""
	}
	return subject, nil
}

func buildSSOSubjectEx(raw map[string]any, externalID string) string {
	payload := map[string]any{
		"source":     "hubmessage_sso",
		"externalID": externalID,
		"syncedAt":   time.Now().Format(time.RFC3339),
		"subject":    raw,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(data)
}

func extractValidEmailFromMap(raw map[string]any, keys ...string) string {
	email := extractStringFromMap(raw, keys...)
	if email == "" {
		return ""
	}
	if regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`).MatchString(email) {
		return email
	}
	return ""
}

func extractAreaCodeFromMap(raw map[string]any, keys ...string) string {
	areaCode := extractStringFromMap(raw, keys...)
	if areaCode == "" {
		return ""
	}
	areaCode = strings.TrimSpace(areaCode)
	if !strings.HasPrefix(areaCode, "+") {
		areaCode = "+" + areaCode
	}
	if regexp.MustCompile(`^\+\d+$`).MatchString(areaCode) {
		return areaCode
	}
	return ""
}

func extractPhoneFromMap(raw map[string]any, keys ...string) string {
	phone := extractStringFromMap(raw, keys...)
	phone = regexp.MustCompile(`\D`).ReplaceAllString(phone, "")
	return phone
}

func logoutSSOSubjectFromRequest(c *gin.Context, cfg ssoConfig) (ssoSubject, bool) {
	raw := map[string]any{}
	for _, key := range []string{"identityId", "operatorIdentityID", "sub", "userID", "userId", "id", "account"} {
		if value := strings.TrimSpace(c.Query(key)); value != "" {
			raw[key] = value
		}
	}
	if c.Request.Method != http.MethodGet && c.Request.Body != nil {
		_ = json.NewDecoder(c.Request.Body).Decode(&raw)
	}
	subject, err := normalizeSSOSubject(cfg, raw)
	return subject, err == nil
}

func postJSONMap(ctx context.Context, cfg ssoConfig, endpoint string, payload any, bearerToken string) (map[string]any, error) {
	var body io.Reader
	if payload != nil {
		data, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return doSSOJSONRequest(cfg, req, bearerToken)
}

func postFormMap(ctx context.Context, cfg ssoConfig, endpoint string, form url.Values, bearerToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return doSSOJSONRequest(cfg, req, bearerToken)
}

func postBasicFormMap(ctx context.Context, cfg ssoConfig, endpoint string, form url.Values) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.SetBasicAuth(cfg.ClientID, cfg.ClientSecret)
	return doSSOJSONRequest(cfg, req, "")
}

func getJSONMap(ctx context.Context, cfg ssoConfig, endpoint string, bearerToken string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	return doSSOJSONRequest(cfg, req, bearerToken)
}

func doSSOJSONRequest(cfg ssoConfig, req *http.Request, bearerToken string) (map[string]any, error) {
	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}
	client := &http.Client{Timeout: defaultSSORequestTimeout}
	if cfg.InsecureSkipVerify {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec
	}
	start := time.Now()
	logSSOOutboundRequest(req)
	resp, err := client.Do(req)
	if err != nil {
		log.ZWarn(req.Context(), "sso outbound request failed", err,
			"method", req.Method,
			"url", req.URL.String(),
			"duration", time.Since(start).String(),
		)
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	logSSOOutboundResponse(req, resp, body, time.Since(start))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		detail := strings.TrimSpace(string(body))
		if detail != "" {
			return nil, errs.ErrInternalServer.WrapMsg(fmt.Sprintf("sso request failed: %s: %s", resp.Status, detail))
		}
		return nil, errs.ErrInternalServer.WrapMsg(fmt.Sprintf("sso request failed: %s", resp.Status))
	}
	var data map[string]any
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, errs.WrapMsg(err, "parse sso json response failed")
	}
	return data, nil
}

func logSSOOutboundRequest(req *http.Request) {
	body := ""
	if req.GetBody != nil {
		if reader, err := req.GetBody(); err == nil {
			data, _ := io.ReadAll(io.LimitReader(reader, 1<<20))
			_ = reader.Close()
			body = sanitizeSSOLogBody(req.Header.Get("Content-Type"), string(data))
		}
	}
	log.ZInfo(req.Context(), "sso outbound request",
		"method", req.Method,
		"url", req.URL.String(),
		"headers", sanitizeSSOLogHeaders(req.Header),
		"body", body,
	)
}

func logSSOOutboundResponse(req *http.Request, resp *http.Response, body []byte, duration time.Duration) {
	log.ZInfo(req.Context(), "sso outbound response",
		"method", req.Method,
		"url", req.URL.String(),
		"status", resp.Status,
		"duration", duration.String(),
		"headers", sanitizeSSOLogHeaders(resp.Header),
		"body", sanitizeSSOLogBody(resp.Header.Get("Content-Type"), string(body)),
	)
}

func sanitizeSSOLogHeaders(headers http.Header) map[string][]string {
	result := make(map[string][]string, len(headers))
	for key, values := range headers {
		if isSensitiveSSOKey(key) {
			result[key] = []string{"****"}
			continue
		}
		copied := make([]string, len(values))
		copy(copied, values)
		result[key] = copied
	}
	return result
}

func sanitizeSSOLogBody(contentType string, body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}
	lowerContentType := strings.ToLower(contentType)
	if strings.Contains(lowerContentType, "application/x-www-form-urlencoded") {
		values, err := url.ParseQuery(body)
		if err != nil {
			return body
		}
		for key := range values {
			if isSensitiveSSOKey(key) {
				values.Set(key, "****")
			}
		}
		return values.Encode()
	}
	if strings.Contains(lowerContentType, "application/json") || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		var value any
		if err := json.Unmarshal([]byte(body), &value); err != nil {
			return body
		}
		value = sanitizeSSOLogValue(value)
		data, err := json.Marshal(value)
		if err != nil {
			return body
		}
		return string(data)
	}
	return body
}

func sanitizeSSOLogValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			if isSensitiveSSOKey(key) {
				typed[key] = "****"
				continue
			}
			typed[key] = sanitizeSSOLogValue(child)
		}
		return typed
	case []any:
		for i, child := range typed {
			typed[i] = sanitizeSSOLogValue(child)
		}
		return typed
	default:
		return value
	}
}

func isSensitiveSSOKey(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "_", "-"))
	return datautil.Contain(normalized,
		"authorization",
		"proxy-authorization",
		"cookie",
		"set-cookie",
		"client-secret",
		"access-token",
		"refresh-token",
		"id-token",
		"token",
		"code",
		"secret",
	)
}

func extractStringFromMap(raw map[string]any, keys ...string) string {
	normalized := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		normalized[normalizeJSONKey(key)] = struct{}{}
	}
	return findStringValue(raw, normalized)
}

func findStringValue(value any, keys map[string]struct{}) string {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if _, ok := keys[normalizeJSONKey(key)]; ok {
				if str := stringifyJSONValue(item); str != "" {
					return str
				}
			}
		}
		for _, item := range v {
			if str := findStringValue(item, keys); str != "" {
				return str
			}
		}
	case []any:
		for _, item := range v {
			if str := findStringValue(item, keys); str != "" {
				return str
			}
		}
	}
	return ""
}

func extractNumberFromMap(raw map[string]any, keys ...string) float64 {
	normalized := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		normalized[normalizeJSONKey(key)] = struct{}{}
	}
	return findNumberValue(raw, normalized)
}

func findNumberValue(value any, keys map[string]struct{}) float64 {
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			if _, ok := keys[normalizeJSONKey(key)]; ok {
				switch num := item.(type) {
				case float64:
					return num
				case int:
					return float64(num)
				case string:
					parsed, _ := strconv.ParseFloat(strings.TrimSpace(num), 64)
					return parsed
				}
			}
		}
		for _, item := range v {
			if num := findNumberValue(item, keys); num != 0 {
				return num
			}
		}
	case []any:
		for _, item := range v {
			if num := findNumberValue(item, keys); num != 0 {
				return num
			}
		}
	}
	return 0
}

func stringifyJSONValue(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatInt(int64(v), 10)
	case int:
		return strconv.Itoa(v)
	case json.Number:
		return v.String()
	default:
		return ""
	}
}

func normalizeJSONKey(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	re := regexp.MustCompile(`[^a-z0-9]`)
	return re.ReplaceAllString(key, "")
}

func mergeJSONMaps(base, extra map[string]any) map[string]any {
	if base == nil {
		return extra
	}
	for key, value := range extra {
		base[key] = value
	}
	return base
}

func buildSSOAccount(prefix string, externalID string) string {
	sum := sha1.Sum([]byte(externalID))
	encoded := hex.EncodeToString(sum[:])
	prefix = regexp.MustCompile(`[^a-zA-Z0-9]`).ReplaceAllString(prefix, "")
	if prefix == "" {
		prefix = "sso"
	}
	return prefix + encoded[:24]
}

func requestOrigin(r *http.Request) string {
	if r == nil {
		return ""
	}
	proto := r.Header.Get("X-Forwarded-Proto")
	if proto == "" {
		if r.TLS != nil {
			proto = "https"
		} else {
			proto = "http"
		}
	}
	host := r.Header.Get("X-Forwarded-Host")
	if host == "" {
		host = r.Host
	}
	if host == "" {
		return ""
	}
	return proto + "://" + host
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	return datautil.Contain(value, "1", "true", "yes", "on")
}

func randomURLToken(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func setSSOStateCookie(c *gin.Context, cfg ssoConfig, state string) {
	secure := strings.HasPrefix(strings.ToLower(cfg.RedirectURI), "https://")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie("hubmessage_sso_state", state, 300, "/", "", secure, true)
}

func validateSSOState(c *gin.Context) error {
	cookieState, err := c.Cookie("hubmessage_sso_state")
	if err != nil || cookieState == "" {
		return nil
	}
	if cookieState != c.Query("state") {
		return errs.ErrNoPermission.WrapMsg("invalid oauth state")
	}
	c.SetCookie("hubmessage_sso_state", "", -1, "/", "", false, true)
	return nil
}

func clientIPOrEmpty(o *Api, c *gin.Context) string {
	ip, err := o.GetClientIP(c)
	if err != nil {
		return ""
	}
	return ip
}

func ssoTextError(c *gin.Context, status int, err error) {
	log.ZWarn(c, "sso request failed", err)
	c.Header("Content-Type", "text/plain; charset=utf-8")
	c.String(status, "单点登录失败：%s", err.Error())
}
