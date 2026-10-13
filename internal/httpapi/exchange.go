package httpapi

import (
	"context"
	"errors"
	"github.com/LeoninCS/shared-auth/internal/auth"
	"github.com/LeoninCS/shared-auth/internal/domain"
	"github.com/gin-gonic/gin"
	"net/http"
)

type tokenExchanger interface {
	Exchange(context.Context, string, string, auth.ExchangeInput) (auth.ExchangeResult, error)
}

func (h handler) exchange(c *gin.Context) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	client, secret, ok := c.Request.BasicAuth()
	exchange, enabled := h.app.(tokenExchanger)
	if !ok || !enabled {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32*1024)
	if err := c.Request.ParseForm(); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}
	form := c.Request.PostForm
	allowed := map[string]bool{"grant_type": true, "subject_token_type": true, "subject_token": true, "resource": true, "scope": true, "import_key": true, "content_digest": true}
	for k, v := range form {
		if !allowed[k] || len(v) != 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}
	}
	if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" || form.Get("subject_token_type") != "urn:ietf:params:oauth:token-type:access_token" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}
	result, err := exchange.Exchange(c.Request.Context(), client, secret, auth.ExchangeInput{SubjectToken: form.Get("subject_token"), Resource: form.Get("resource"), Scope: form.Get("scope"), ImportKey: form.Get("import_key"), ContentDigest: form.Get("content_digest")})
	if err != nil {
		status, code := http.StatusInternalServerError, "server_error"
		if errors.Is(err, domain.ErrUnauthorized) {
			status, code = http.StatusUnauthorized, "invalid_grant"
		}
		if errors.Is(err, domain.ErrInvalidInput) {
			status, code = http.StatusBadRequest, "invalid_request"
		}
		c.JSON(status, gin.H{"error": code})
		return
	}
	c.JSON(http.StatusOK, result)
}
