package verification

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

const resendEmailsEndpoint = "https://api.resend.com/emails"

var ErrDeliveryFailed = errors.New("verification delivery failed")

type ResendSender struct {
	apiKey   string
	from     string
	endpoint string
	client   *http.Client
}

type resendEmailRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
	Text    string   `json:"text"`
}

func NewResendSender(apiKey, from string, client *http.Client) (*ResendSender, error) {
	apiKey = strings.TrimSpace(apiKey)
	from = strings.TrimSpace(from)
	if apiKey == "" {
		return nil, errors.New("resend API key is required")
	}
	if _, err := mail.ParseAddress(from); err != nil {
		return nil, fmt.Errorf("invalid resend from address: %w", err)
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &ResendSender{apiKey: apiKey, from: from, endpoint: resendEmailsEndpoint, client: client}, nil
}

func (s *ResendSender) Send(ctx context.Context, delivery Delivery) error {
	subject, plainText, htmlBody := verificationEmail(delivery)
	payload, err := json.Marshal(resendEmailRequest{
		From: s.from, To: []string{delivery.Identifier}, Subject: subject,
		HTML: htmlBody, Text: plainText,
	})
	if err != nil {
		return fmt.Errorf("%w: encode request: %v", ErrDeliveryFailed, err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("%w: create request: %v", ErrDeliveryFailed, err)
	}
	request.Header.Set("Authorization", "Bearer "+s.apiKey)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "shared-auth/1.0")

	response, err := s.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: request failed: %v", ErrDeliveryFailed, err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return fmt.Errorf("%w: resend returned %d: %s", ErrDeliveryFailed, response.StatusCode, strings.TrimSpace(string(body)))
	}
	_, _ = io.Copy(io.Discard, response.Body)
	return nil
}

func verificationEmail(delivery Delivery) (subject, plainText, htmlBody string) {
	product := productName(delivery.ClientID)
	action := "完成注册"
	subject = product + " 注册验证码"
	if delivery.Purpose == "reset" {
		action = "重置密码"
		subject = product + " 密码重置验证码"
	}
	duration := time.Until(delivery.ExpiresAt)
	if !delivery.CreatedAt.IsZero() {
		duration = delivery.ExpiresAt.Sub(delivery.CreatedAt)
	}
	minutes := int(duration.Minutes())
	if minutes < 1 {
		minutes = 1
	}
	plainText = fmt.Sprintf("你正在为 %s %s。\n\n验证码：%s\n\n验证码将在 %d 分钟后失效，请勿将验证码告诉他人。\n如果不是你本人操作，可以忽略这封邮件。", product, action, delivery.Code, minutes)
	htmlBody = fmt.Sprintf(`<!doctype html>
<html lang="zh-CN"><body style="margin:0;background:#f5f7fb;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','Microsoft YaHei',sans-serif;color:#182230">
<div style="max-width:520px;margin:32px auto;padding:0 16px">
  <div style="background:#fff;border:1px solid #e4e8ef;border-radius:14px;padding:32px">
    <div style="font-size:20px;font-weight:700;margin-bottom:20px">%s</div>
    <p style="margin:0 0 18px;line-height:1.7">你正在%s，请使用下面的验证码：</p>
    <div style="font-size:34px;font-weight:700;letter-spacing:8px;background:#f0f5ff;color:#2458d3;text-align:center;border-radius:10px;padding:18px 12px">%s</div>
    <p style="margin:18px 0 0;color:#667085;font-size:14px;line-height:1.7">验证码将在 %d 分钟后失效，请勿将验证码告诉他人。<br>如果不是你本人操作，可以忽略这封邮件。</p>
  </div>
</div></body></html>`, html.EscapeString(product), html.EscapeString(action), html.EscapeString(delivery.Code), minutes)
	return subject, plainText, htmlBody
}

func productName(clientID string) string {
	switch clientID {
	case "jobpilot":
		return "JobPilot"
	case "studyflow":
		return "StudyFlow"
	default:
		return "账号中心"
	}
}
