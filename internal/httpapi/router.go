package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/LeoninCS/shared-auth/internal/auth"
	"github.com/LeoninCS/shared-auth/internal/domain"
	"github.com/LeoninCS/shared-auth/internal/token"
	"github.com/LeoninCS/shared-auth/internal/verification"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Application interface {
	Client(context.Context, string, string) (domain.Client, error)
	RequestVerification(context.Context, auth.VerificationInput, auth.RequestMeta) (auth.VerificationResult, error)
	Register(context.Context, auth.RegisterInput, auth.RequestMeta) (auth.IssueResult, error)
	Login(context.Context, auth.LoginInput, auth.RequestMeta) (auth.IssueResult, error)
	Refresh(context.Context, string, string, auth.RequestMeta) (auth.RefreshResult, error)
	Logout(context.Context, string, string, auth.RequestMeta) (domain.Client, error)
	Account(context.Context, token.Principal) (domain.UserAccount, error)
	DeleteAccount(context.Context, token.Principal, string, auth.RequestMeta) (domain.Client, error)
	ResetPassword(context.Context, auth.ChallengeInput, auth.RequestMeta) error
	ParseAccessToken(string) (token.Principal, error)
	JWKS() token.JWKS
}

type Dependencies struct {
	Application    Application
	Ready          func() error
	Outbox         *verification.DevOutbox
	CookieSecure   bool
	AllowedOrigins []string
}

type handler struct {
	app          Application
	outbox       *verification.DevOutbox
	cookieSecure bool
}

const principalKey = "auth-principal"

func NewRouter(dependencies Dependencies) *gin.Engine {
	router := gin.New()
	_ = router.SetTrustedProxies(nil)
	router.Use(requestID(), requestLogger(), gin.Recovery(), cors(dependencies.AllowedOrigins))
	h := handler{app: dependencies.Application, outbox: dependencies.Outbox, cookieSecure: dependencies.CookieSecure}

	router.GET("/health/live", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/health/ready", func(c *gin.Context) {
		if dependencies.Ready != nil {
			if err := dependencies.Ready(); err != nil {
				writeError(c, http.StatusServiceUnavailable, "not_ready", "数据库暂不可用")
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	router.GET("/.well-known/jwks.json", func(c *gin.Context) {
		c.JSON(http.StatusOK, dependencies.Application.JWKS())
	})

	api := router.Group("/auth/v1")
	{
		api.POST("/verifications", h.verifications)
		api.POST("/register", h.register)
		api.POST("/login", h.login)
		api.POST("/token/refresh", h.refresh)
		api.POST("/logout", h.logout)
		api.GET("/me", h.requireAccess(), h.me)
		api.DELETE("/me", h.requireAccess(), h.deleteAccount)
		api.POST("/password/reset", h.resetPassword)
	}
	if dependencies.Outbox != nil {
		router.GET("/dev/outbox", h.devOutbox)
	}
	router.NoRoute(func(c *gin.Context) {
		writeError(c, http.StatusNotFound, "route_not_found", "没有找到该接口")
	})
	return router
}

func (h handler) verifications(c *gin.Context) {
	var request struct {
		ClientID string `json:"client_id" binding:"required"`
		Email    string `json:"email" binding:"required"`
		Purpose  string `json:"purpose" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "验证码请求格式不正确")
		return
	}
	result, err := h.app.RequestVerification(c, auth.VerificationInput{
		ClientID: request.ClientID, Email: request.Email, Purpose: request.Purpose,
	}, metadata(c))
	if err != nil {
		handleError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, gin.H{"data": result})
}

func (h handler) register(c *gin.Context) {
	var request struct {
		ClientID    string    `json:"client_id" binding:"required"`
		ChallengeID uuid.UUID `json:"challenge_id" binding:"required"`
		Code        string    `json:"code" binding:"required"`
		Password    string    `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.ChallengeID == uuid.Nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "注册信息格式不正确")
		return
	}
	result, err := h.app.Register(c, auth.RegisterInput{
		ClientID: request.ClientID, ChallengeID: request.ChallengeID,
		Code: request.Code, Password: request.Password,
	}, metadata(c))
	if err != nil {
		handleError(c, err)
		return
	}
	h.setRefreshCookie(c, result.Client, result.RefreshToken, result.RefreshUntil)
	c.JSON(http.StatusCreated, gin.H{"data": publicIssue(result)})
}

func (h handler) login(c *gin.Context) {
	var request struct {
		ClientID string `json:"client_id" binding:"required"`
		Email    string `json:"email" binding:"required"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "登录信息格式不正确")
		return
	}
	result, err := h.app.Login(c, auth.LoginInput{ClientID: request.ClientID, Email: request.Email, Password: request.Password}, metadata(c))
	if err != nil {
		handleError(c, err)
		return
	}
	h.setRefreshCookie(c, result.Client, result.RefreshToken, result.RefreshUntil)
	c.JSON(http.StatusOK, gin.H{"data": publicIssue(result)})
}

func (h handler) refresh(c *gin.Context) {
	var request struct {
		ClientID string `json:"client_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "刷新请求格式不正确")
		return
	}
	client, err := h.app.Client(c, request.ClientID, c.GetHeader("Origin"))
	if err != nil {
		handleError(c, err)
		return
	}
	rawRefresh, err := c.Cookie(client.CookieName)
	if err != nil {
		handleError(c, domain.ErrUnauthorized)
		return
	}
	result, err := h.app.Refresh(c, client.ID, rawRefresh, metadata(c))
	if err != nil {
		handleError(c, err)
		return
	}
	h.setRefreshCookie(c, result.Client, result.RefreshToken, result.RefreshUntil)
	c.JSON(http.StatusOK, gin.H{"data": publicIssue(result.IssueResult)})
}

func (h handler) logout(c *gin.Context) {
	var request struct {
		ClientID string `json:"client_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "退出请求格式不正确")
		return
	}
	client, err := h.app.Client(c, request.ClientID, c.GetHeader("Origin"))
	if err != nil {
		handleError(c, err)
		return
	}
	rawRefresh, _ := c.Cookie(client.CookieName)
	client, err = h.app.Logout(c, client.ID, rawRefresh, metadata(c))
	if err != nil {
		handleError(c, err)
		return
	}
	h.clearRefreshCookie(c, client)
	c.Status(http.StatusNoContent)
}

func (h handler) me(c *gin.Context) {
	principal := mustPrincipal(c)
	if _, err := h.app.Client(c, principal.ClientID, c.GetHeader("Origin")); err != nil {
		handleError(c, err)
		return
	}
	account, err := h.app.Account(c, principal)
	if err != nil {
		handleError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": account})
}

func (h handler) deleteAccount(c *gin.Context) {
	var request struct {
		CurrentPassword string `json:"current_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "请输入当前密码确认注销")
		return
	}
	client, err := h.app.DeleteAccount(c, mustPrincipal(c), request.CurrentPassword, metadata(c))
	if err != nil {
		handleError(c, err)
		return
	}
	h.clearRefreshCookie(c, client)
	c.Status(http.StatusNoContent)
}

func (h handler) resetPassword(c *gin.Context) {
	var request struct {
		ClientID    string    `json:"client_id" binding:"required"`
		ChallengeID uuid.UUID `json:"challenge_id" binding:"required"`
		Code        string    `json:"code" binding:"required"`
		NewPassword string    `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&request); err != nil || request.ChallengeID == uuid.Nil {
		writeError(c, http.StatusBadRequest, "invalid_request", "密码重置信息格式不正确")
		return
	}
	err := h.app.ResetPassword(c, auth.ChallengeInput{
		ClientID: request.ClientID, ChallengeID: request.ChallengeID,
		Code: request.Code, Password: request.NewPassword,
	}, metadata(c))
	if err != nil {
		handleError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h handler) devOutbox(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"data": h.outbox.List(strings.TrimSpace(c.Query("identifier")))})
}

func (h handler) requireAccess() gin.HandlerFunc {
	return func(c *gin.Context) {
		principal, err := h.parseAuthorization(c)
		if err != nil {
			handleError(c, err)
			c.Abort()
			return
		}
		c.Set(principalKey, principal)
		c.Next()
	}
}

func (h handler) parseAuthorization(c *gin.Context) (token.Principal, error) {
	value := c.GetHeader("Authorization")
	prefix := "Bearer "
	if !strings.HasPrefix(value, prefix) || len(value) <= len(prefix) {
		return token.Principal{}, domain.ErrUnauthorized
	}
	principal, err := h.app.ParseAccessToken(strings.TrimSpace(strings.TrimPrefix(value, prefix)))
	if err != nil {
		return token.Principal{}, domain.ErrUnauthorized
	}
	return principal, nil
}

func mustPrincipal(c *gin.Context) token.Principal {
	value, _ := c.Get(principalKey)
	principal, _ := value.(token.Principal)
	return principal
}

func metadata(c *gin.Context) auth.RequestMeta {
	return auth.RequestMeta{Origin: c.GetHeader("Origin"), SourceIP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

func (h handler) setRefreshCookie(c *gin.Context, client domain.Client, value string, expiresAt time.Time) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: client.CookieName, Value: value, Path: "/auth", HttpOnly: true,
		Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: max(1, int(time.Until(expiresAt).Seconds())), Expires: expiresAt,
	})
}

func (h handler) clearRefreshCookie(c *gin.Context, client domain.Client) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: client.CookieName, Value: "", Path: "/auth", HttpOnly: true,
		Secure: h.cookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: -1, Expires: time.Unix(1, 0),
	})
}

func publicIssue(result auth.IssueResult) gin.H {
	return gin.H{
		"account": result.Account, "access_token": result.AccessToken,
		"token_type": result.TokenType, "expires_at": result.ExpiresAt,
	}
}

func handleError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		writeError(c, http.StatusBadRequest, "invalid_request", "请求内容不完整或格式不正确")
	case errors.Is(err, domain.ErrInvalidCredentials):
		writeError(c, http.StatusUnauthorized, "invalid_credentials", "邮箱或密码错误")
	case errors.Is(err, domain.ErrPasswordMismatch):
		writeError(c, http.StatusUnauthorized, "invalid_password", "当前密码错误")
	case errors.Is(err, domain.ErrVerificationFailed), errors.Is(err, domain.ErrNotFound):
		writeError(c, http.StatusUnprocessableEntity, "verification_failed", "验证码无效、已过期或已被使用")
	case errors.Is(err, domain.ErrIdentityExists):
		writeError(c, http.StatusConflict, "identity_unavailable", "该邮箱不能用于创建账号")
	case errors.Is(err, domain.ErrUnauthorized):
		writeError(c, http.StatusUnauthorized, "unauthorized", "登录状态无效或已经过期")
	case errors.Is(err, domain.ErrForbidden):
		writeError(c, http.StatusForbidden, "forbidden", "当前应用无权执行此操作")
	case errors.Is(err, domain.ErrRateLimited):
		c.Header("Retry-After", "60")
		writeError(c, http.StatusTooManyRequests, "rate_limited", "操作过于频繁，请稍后重试")
	case errors.Is(err, domain.ErrClientNotFound):
		writeError(c, http.StatusBadRequest, "invalid_client", "客户端标识无效")
	case errors.Is(err, verification.ErrDeliveryFailed), errors.Is(err, verification.ErrProviderNotConfigured):
		slog.Error("verification delivery failed", "request_id", requestIDValue(c), "error", err)
		writeError(c, http.StatusServiceUnavailable, "email_delivery_failed", "验证码邮件暂时无法发送，请稍后重试")
	default:
		slog.Error("auth request failed", "request_id", requestIDValue(c), "error", err)
		writeError(c, http.StatusInternalServerError, "internal_error", "服务暂时无法完成请求")
	}
}

func writeError(c *gin.Context, status int, code, message string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": message, "request_id": requestIDValue(c)}})
}

func requestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		value := strings.TrimSpace(c.GetHeader("X-Request-ID"))
		if value == "" || len(value) > 128 {
			value = uuid.NewString()
		}
		c.Set("request-id", value)
		c.Header("X-Request-ID", value)
		c.Next()
	}
}

func requestIDValue(c *gin.Context) string {
	value, _ := c.Get("request-id")
	result, _ := value.(string)
	return result
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		started := time.Now()
		c.Next()
		slog.Info("http request", "request_id", requestIDValue(c), "method", c.Request.Method,
			"path", c.Request.URL.Path, "status", c.Writer.Status(), "duration_ms", time.Since(started).Milliseconds())
	}
}

func cors(allowedOrigins []string) gin.HandlerFunc {
	allowed := make(map[string]struct{}, len(allowedOrigins))
	for _, origin := range allowedOrigins {
		allowed[origin] = struct{}{}
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if _, ok := allowed[origin]; ok {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
			c.Header("Access-Control-Allow-Credentials", "true")
			c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if c.Request.Method == http.MethodOptions {
			if origin != "" {
				if _, ok := allowed[origin]; !ok {
					writeError(c, http.StatusForbidden, "forbidden", "当前来源不在允许列表中")
					c.Abort()
					return
				}
			}
			c.Status(http.StatusNoContent)
			c.Abort()
			return
		}
		c.Next()
	}
}
