package verification

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestResendSenderSendsVerificationEmail(t *testing.T) {
	var received resendEmailRequest
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer re_test" {
			t.Fatalf("unexpected request method or authorization header")
		}
		if request.Header.Get("User-Agent") != "shared-auth/1.0" {
			t.Fatalf("unexpected user agent: %q", request.Header.Get("User-Agent"))
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Fatal(err)
		}
		writer.WriteHeader(http.StatusCreated)
		_, _ = writer.Write([]byte(`{"id":"email-id"}`))
	}))
	defer server.Close()

	sender, err := NewResendSender("re_test", "Account Center <verify@example.com>", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	sender.endpoint = server.URL
	createdAt := time.Date(2026, 9, 17, 8, 0, 0, 0, time.UTC)
	err = sender.Send(context.Background(), Delivery{
		ChallengeID: uuid.New(), ClientID: "jobpilot", Identifier: "person@gmail.com",
		Purpose: "register", Code: "123456", CreatedAt: createdAt, ExpiresAt: createdAt.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if received.From != "Account Center <verify@example.com>" || len(received.To) != 1 || received.To[0] != "person@gmail.com" {
		t.Fatalf("unexpected recipients: %+v", received)
	}
	if !strings.Contains(received.Subject, "JobPilot") || !strings.Contains(received.Text, "123456") || !strings.Contains(received.HTML, "123456") {
		t.Fatalf("verification content is incomplete: %+v", received)
	}
}

func TestResendSenderReportsProviderError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusForbidden)
		_, _ = writer.Write([]byte(`{"message":"domain is not verified"}`))
	}))
	defer server.Close()

	sender, err := NewResendSender("re_test", "verify@example.com", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	sender.endpoint = server.URL
	err = sender.Send(context.Background(), Delivery{
		ClientID: "studyflow", Identifier: "person@gmail.com", Purpose: "reset",
		Code: "654321", CreatedAt: time.Now(), ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if !errors.Is(err, ErrDeliveryFailed) {
		t.Fatalf("expected delivery failure, got %v", err)
	}
}

func TestNewResendSenderValidatesConfiguration(t *testing.T) {
	if _, err := NewResendSender("", "verify@example.com", nil); err == nil {
		t.Fatal("accepted an empty API key")
	}
	if _, err := NewResendSender("re_test", "not-an-address", nil); err == nil {
		t.Fatal("accepted an invalid from address")
	}
}
