package push

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"xam/linux_server/internal/config"
)

const ScopeFirebaseMessaging = "https://www.googleapis.com/auth/firebase.messaging"

var ErrPushTokenInvalid = errors.New("push token is invalid")

type Sender interface {
	SendActivity(ctx context.Context, pushToken string) error
}

type NoopSender struct{}

func (NoopSender) SendActivity(ctx context.Context, pushToken string) error {
	return nil
}

type FCMSender struct {
	projectID  string
	httpClient *http.Client
	logger     *slog.Logger
}

func New(cfg config.Config, logger *slog.Logger) (Sender, error) {
	credentialsJSON, err := readCredentialsJSON(cfg)
	if err != nil {
		return nil, err
	}
	if len(credentialsJSON) == 0 {
		logger.Info("push notifications disabled: no FCM credentials configured")
		return NoopSender{}, nil
	}

	creds, err := google.CredentialsFromJSON(context.Background(), credentialsJSON, ScopeFirebaseMessaging)
	if err != nil {
		return nil, fmt.Errorf("load FCM credentials: %w", err)
	}

	projectID := strings.TrimSpace(cfg.FCMProjectID)
	if projectID == "" {
		projectID = extractProjectID(credentialsJSON)
	}
	if projectID == "" {
		return nil, errors.New("FCM project id is required")
	}

	return &FCMSender{
		projectID: projectID,
		httpClient: &http.Client{
			Transport: &oauthTransport{
				base:   http.DefaultTransport,
				source: creds.TokenSource,
			},
			Timeout: 15 * time.Second,
		},
		logger: logger,
	}, nil
}

func readCredentialsJSON(cfg config.Config) ([]byte, error) {
	if value := strings.TrimSpace(cfg.FCMCredentialsJSON); value != "" {
		return []byte(value), nil
	}
	if path := strings.TrimSpace(cfg.FCMCredentialsFile); path != "" {
		return os.ReadFile(path)
	}
	return nil, nil
}

func extractProjectID(credentialsJSON []byte) string {
	var payload struct {
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(credentialsJSON, &payload); err != nil {
		return ""
	}
	return strings.TrimSpace(payload.ProjectID)
}

func (s *FCMSender) SendActivity(ctx context.Context, pushToken string) error {
	pushToken = strings.TrimSpace(pushToken)
	if pushToken == "" {
		return nil
	}

	requestBody := map[string]any{
		"message": map[string]any{
			"token": pushToken,
			"data": map[string]string{
				"activity": "1",
				"scope":    "inbox",
			},
			"android": map[string]any{
				"priority": "high",
			},
		},
	}

	body, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("https://fcm.googleapis.com/v1/projects/%s/messages:send", s.projectID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}

	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	if isInvalidTokenResponse(resp.StatusCode, responseBody) {
		return ErrPushTokenInvalid
	}
	s.logger.Warn("push send failed", "status_code", resp.StatusCode, "body", string(responseBody))
	return fmt.Errorf("push send failed: http %d", resp.StatusCode)
}

func isInvalidTokenResponse(statusCode int, body []byte) bool {
	if statusCode != http.StatusBadRequest && statusCode != http.StatusNotFound {
		return false
	}
	text := strings.ToUpper(string(body))
	return strings.Contains(text, "UNREGISTERED") ||
		strings.Contains(text, "INVALID_ARGUMENT") ||
		strings.Contains(text, "INVALID_REGISTRATION")
}

type oauthTransport struct {
	base   http.RoundTripper
	source oauth2.TokenSource
}

func (t *oauthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.source.Token()
	if err != nil {
		return nil, err
	}
	clone := req.Clone(req.Context())
	clone.Header = req.Header.Clone()
	clone.Header.Set("Authorization", "Bearer "+token.AccessToken)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(clone)
}
