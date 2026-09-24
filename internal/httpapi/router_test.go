package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LeoninCS/shared-auth/internal/auth"
	"github.com/LeoninCS/shared-auth/internal/domain"
	"github.com/LeoninCS/shared-auth/internal/token"
	"github.com/google/uuid"
)

type fakeApplication struct {
	loginResult  auth.IssueResult
	loginErr     error
	principal    token.Principal
	deleteClient domain.Client
	deleteErr    error
}

func (f fakeApplication) Client(_ context.Context, id, origin string) (domain.Client, error) {
	if id != "jobpilot" {
		return domain.Client{}, domain.ErrClientNotFound
	}
	if origin != "" && origin != "http://localhost:5173" {
		return domain.Client{}, domain.ErrForbidden
	}
	return domain.Client{ID: "jobpilot", Audience: "jobpilot", CookieName: "jp_refresh", Enabled: true, AllowedOrigins: []string{"http://localhost:5173"}}, nil
}
func (fakeApplication) RequestVerification(context.Context, auth.VerificationInput, auth.RequestMeta) (auth.VerificationResult, error) {
	panic("unexpected call")
}
func (fakeApplication) Register(context.Context, auth.RegisterInput, auth.RequestMeta) (auth.IssueResult, error) {
	panic("unexpected call")
}
func (f fakeApplication) Login(context.Context, auth.LoginInput, auth.RequestMeta) (auth.IssueResult, error) {
	return f.loginResult, f.loginErr
}
func (fakeApplication) Refresh(context.Context, string, string, auth.RequestMeta) (auth.RefreshResult, error) {
	panic("unexpected call")
}
func (fakeApplication) Logout(context.Context, string, string, auth.RequestMeta) (domain.Client, error) {
	panic("unexpected call")
}
func (fakeApplication) Account(context.Context, token.Principal) (domain.UserAccount, error) {
	panic("unexpected call")
}
func (f fakeApplication) DeleteAccount(context.Context, token.Principal, string, auth.RequestMeta) (domain.Client, error) {
	return f.deleteClient, f.deleteErr
}
func (fakeApplication) ResetPassword(context.Context, auth.ChallengeInput, auth.RequestMeta) error {
	panic("unexpected call")
}
func (f fakeApplication) ParseAccessToken(string) (token.Principal, error) {
	if f.principal.UserID == uuid.Nil {
		return token.Principal{}, domain.ErrUnauthorized
	}
	return f.principal, nil
}
func (fakeApplication) JWKS() token.JWKS { return token.JWKS{} }

func TestLoginSetsProtectedRefreshCookie(t *testing.T) {
	client := domain.Client{ID: "jobpilot", Audience: "jobpilot", CookieName: "jp_refresh"}
	app := fakeApplication{loginResult: auth.IssueResult{
		Account:     domain.UserAccount{User: domain.User{ID: uuid.New(), Status: "active"}},
		AccessToken: "access", TokenType: "Bearer", ExpiresAt: time.Now().Add(15 * time.Minute),
		RefreshToken: "refresh", RefreshUntil: time.Now().Add(time.Hour), Client: client,
	}}
	router := NewRouter(Dependencies{Application: app, AllowedOrigins: []string{"http://localhost:5173"}})
	recorder := httptest.NewRecorder()
	body, _ := json.Marshal(map[string]string{"client_id": "jobpilot", "email": "person@example.com", "password": "password"})
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/login", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Origin", "http://localhost:5173")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	cookie := recorder.Header().Get("Set-Cookie")
	for _, required := range []string{"jp_refresh=refresh", "Path=/auth", "HttpOnly", "SameSite=Lax"} {
		if !strings.Contains(cookie, required) {
			t.Fatalf("cookie %q does not contain %q", cookie, required)
		}
	}
	if strings.Contains(cookie, "Secure") {
		t.Fatalf("development cookie unexpectedly has Secure: %s", cookie)
	}
	if recorder.Header().Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal("credentialed CORS header is missing")
	}
}

func TestErrorEnvelopeContainsRequestID(t *testing.T) {
	router := NewRouter(Dependencies{Application: fakeApplication{loginErr: domain.ErrInvalidCredentials}})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/auth/v1/login", strings.NewReader(`{"client_id":"jobpilot","email":"person@example.com","password":"wrong-password"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Request-ID", "test-request")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized || !strings.Contains(recorder.Body.String(), `"code":"invalid_credentials"`) || !strings.Contains(recorder.Body.String(), `"request_id":"test-request"`) {
		t.Fatalf("unexpected error response: %d %s", recorder.Code, recorder.Body.String())
	}
}

func TestUnknownOriginPreflightIsRejected(t *testing.T) {
	router := NewRouter(Dependencies{Application: fakeApplication{}, AllowedOrigins: []string{"http://localhost:5173"}})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodOptions, "/auth/v1/login", nil)
	request.Header.Set("Origin", "https://attacker.example")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestDevOutboxRouteIsAbsentWhenDisabled(t *testing.T) {
	router := NewRouter(Dependencies{Application: fakeApplication{}})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dev/outbox", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestIdentityBindingRouteWasRemoved(t *testing.T) {
	router := NewRouter(Dependencies{Application: fakeApplication{}})
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/auth/v1/identities", strings.NewReader(`{}`)))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("removed identity route status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestDeleteAccountClearsCurrentClientCookie(t *testing.T) {
	userID := uuid.New()
	client := domain.Client{ID: "jobpilot", Audience: "jobpilot", CookieName: "jp_refresh", Enabled: true, AllowedOrigins: []string{"http://localhost:5173"}}
	router := NewRouter(Dependencies{Application: fakeApplication{
		principal:    token.Principal{UserID: userID, SessionID: uuid.New(), ClientID: "jobpilot"},
		deleteClient: client,
	}, AllowedOrigins: []string{"http://localhost:5173"}})
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodDelete, "/auth/v1/me", strings.NewReader(`{"current_password":"correct-password"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer access-token")
	request.Header.Set("Origin", "http://localhost:5173")
	router.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	cookie := recorder.Header().Get("Set-Cookie")
	for _, required := range []string{"jp_refresh=", "Path=/auth", "HttpOnly", "Max-Age=0"} {
		if !strings.Contains(cookie, required) {
			t.Fatalf("cookie %q does not contain %q", cookie, required)
		}
	}
}
