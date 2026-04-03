package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"xam/linux_server/internal/auth"
	"xam/linux_server/internal/config"
	"xam/linux_server/internal/debuglog"
	"xam/linux_server/internal/ratelimit"
	"xam/linux_server/internal/service"
	"xam/linux_server/internal/storage"
)

type ctxKey string

const deviceIDKey ctxKey = "deviceID"
const requestIDKey ctxKey = "requestID"

type Server struct {
	cfg         config.Config
	logger      *slog.Logger
	service     *service.Service
	tokens      *auth.TokenManager
	logbook     *debuglog.LogBook
	authLimiter *ratelimit.Limiter
	sendLimiter *ratelimit.Limiter
	pullLimiter *ratelimit.Limiter
}

func New(cfg config.Config, logger *slog.Logger, svc *service.Service, tokens *auth.TokenManager, logbook *debuglog.LogBook) *Server {
	return &Server{
		cfg:         cfg,
		logger:      logger,
		service:     svc,
		tokens:      tokens,
		logbook:     logbook,
		authLimiter: ratelimit.New(cfg.AuthRatePerMinute, time.Minute),
		sendLimiter: ratelimit.New(cfg.SendRatePerMinute, time.Minute),
		pullLimiter: ratelimit.New(cfg.PullRatePerMinute, time.Minute),
	}
}

func (s *Server) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /devices/register", s.handleRegister)
	mux.HandleFunc("POST /auth/challenge", s.handleChallenge)
	mux.HandleFunc("POST /auth/verify", s.handleVerify)
	mux.Handle("POST /messages", s.withAuth(s.handleSendMessage))
	mux.Handle("GET /messages/pull", s.withAuth(s.handlePullMessages))
	mux.Handle("POST /messages/ack-delete", s.withAuth(s.handleAckDelete))
	mux.Handle("POST /attachments/upload-init", s.withAuth(s.handleUploadInit))
	mux.Handle("GET /attachments/download", s.withAuth(s.handleDownloadAttachment))
	if s.cfg.DebugAPIEnabled {
		mux.HandleFunc("POST /debug/bootstrap", s.handleDebugBootstrap)
		mux.HandleFunc("POST /debug/resolve-device", s.handleDebugResolveDevice)
		mux.HandleFunc("GET /debug/logs", s.handleDebugLogs)
	}

	return s.withRequestID(s.withLogging(mux))
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.service.Health(ctx); err != nil {
		s.writeError(w, http.StatusServiceUnavailable, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var input service.RegisterDeviceInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	device, err := s.service.RegisterDevice(r.Context(), input)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, device)
}

func (s *Server) handleChallenge(w http.ResponseWriter, r *http.Request) {
	key := clientKey(r)
	if !s.authLimiter.Allow(key, time.Now()) {
		s.writeError(w, http.StatusTooManyRequests, service.ErrRateLimited)
		return
	}
	var input service.CreateChallengeInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	challenge, err := s.service.CreateChallenge(r.Context(), input)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"challenge_id": challenge.ID,
		"device_id":    challenge.DeviceID,
		"nonce":        challenge.Nonce,
		"expires_at":   challenge.ExpiresAt,
	})
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	key := clientKey(r)
	if !s.authLimiter.Allow(key, time.Now()) {
		s.writeError(w, http.StatusTooManyRequests, service.ErrRateLimited)
		return
	}
	var input service.VerifyChallengeInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	token, expiresAt, deviceID, err := s.service.VerifyChallenge(r.Context(), input)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_at":   expiresAt,
		"device_id":    deviceID,
	})
}

func (s *Server) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	deviceID := deviceIDFromContext(r.Context())
	if !s.sendLimiter.Allow(deviceID, time.Now()) {
		s.writeError(w, http.StatusTooManyRequests, service.ErrRateLimited)
		return
	}
	var input service.SendMessageInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	input.IdempotencyKey = r.Header.Get("Idempotency-Key")
	message, err := s.service.SendMessage(r.Context(), deviceID, input)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, message)
}

func (s *Server) handlePullMessages(w http.ResponseWriter, r *http.Request) {
	deviceID := deviceIDFromContext(r.Context())
	if !s.pullLimiter.Allow(deviceID, time.Now()) {
		s.writeError(w, http.StatusTooManyRequests, service.ErrRateLimited)
		return
	}
	limit := s.cfg.PullLimitDefault
	if raw := r.URL.Query().Get("limit"); raw != "" {
		var parsed int
		if _, err := fmt.Sscanf(raw, "%d", &parsed); err == nil {
			limit = parsed
		}
	}
	messages, err := s.service.PullMessages(r.Context(), deviceID, limit)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": messages})
}

func (s *Server) handleAckDelete(w http.ResponseWriter, r *http.Request) {
	deviceID := deviceIDFromContext(r.Context())
	var payload struct {
		MessageIDs []string `json:"message_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	deleted, err := s.service.AckDeleteMessages(r.Context(), deviceID, payload.MessageIDs)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": deleted})
}

func (s *Server) handleUploadInit(w http.ResponseWriter, r *http.Request) {
	deviceID := deviceIDFromContext(r.Context())
	if !s.sendLimiter.Allow(deviceID, time.Now()) {
		s.writeError(w, http.StatusTooManyRequests, service.ErrRateLimited)
		return
	}
	var input service.UploadInitInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	attachment, uploadURL, err := s.service.InitAttachmentUpload(r.Context(), deviceID, input)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"attachment": attachment,
		"upload_url": uploadURL,
	})
}

func (s *Server) handleDownloadAttachment(w http.ResponseWriter, r *http.Request) {
	deviceID := deviceIDFromContext(r.Context())
	attachmentID := r.URL.Query().Get("attachment_id")
	if attachmentID == "" {
		s.writeError(w, http.StatusBadRequest, errors.New("attachment_id is required"))
		return
	}
	attachment, downloadURL, err := s.service.AttachmentDownloadURL(r.Context(), deviceID, attachmentID)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"attachment":   attachment,
		"download_url": downloadURL,
	})
}

func (s *Server) handleDebugBootstrap(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DebugAPIEnabled {
		s.writeError(w, http.StatusNotFound, errors.New("debug api is disabled"))
		return
	}
	var payload struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	device, created, err := s.service.EnsureDebugDevice(r.Context(), payload.PublicKey)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	token, expiresAt, err := s.service.IssueDebugToken(r.Context(), device.ID)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id":     device.ID,
		"access_token":  token,
		"expires_at":    expiresAt,
		"created":       created,
		"debug_enabled": true,
	})
}

func (s *Server) handleDebugResolveDevice(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DebugAPIEnabled {
		s.writeError(w, http.StatusNotFound, errors.New("debug api is disabled"))
		return
	}
	var payload struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		s.writeError(w, http.StatusBadRequest, err)
		return
	}
	device, err := s.service.ResolveDeviceByPublicKey(r.Context(), payload.PublicKey)
	if err != nil {
		s.writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": device.ID,
		"status":    device.Status,
	})
}

func (s *Server) handleDebugLogs(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.DebugAPIEnabled {
		s.writeError(w, http.StatusNotFound, errors.New("debug api is disabled"))
		return
	}
	limit := 200
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entries": s.logbook.List(limit),
	})
}

func (s *Server) withAuth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			s.writeError(w, http.StatusUnauthorized, service.ErrUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := s.tokens.Parse(token)
		if err != nil {
			s.writeError(w, http.StatusUnauthorized, service.ErrUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), deviceIDKey, claims.DeviceID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
		}
		w.Header().Set("X-Request-ID", requestID)
		ctx := context.WithValue(r.Context(), requestIDKey, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(recorder, r)

		fields := map[string]any{
			"request_id":    requestIDFromContext(r.Context()),
			"method":        r.Method,
			"path":          r.URL.Path,
			"query":         r.URL.RawQuery,
			"remote_addr":   r.RemoteAddr,
			"user_agent":    r.UserAgent(),
			"status":        recorder.status,
			"bytes":         recorder.bytes,
			"duration_ms":   time.Since(start).Milliseconds(),
			"device_id":     deviceIDFromContext(r.Context()),
			"forwarded_for": r.Header.Get("X-Forwarded-For"),
		}
		args := make([]any, 0, len(fields)*2)
		for key, value := range fields {
			args = append(args, key, value)
		}
		s.logger.Info("http request", args...)
		if s.logbook != nil {
			s.logbook.Add(slog.LevelInfo, "http request", fields)
		}
	})
}

func (s *Server) writeServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, service.ErrInvalidInput):
		s.writeError(w, http.StatusBadRequest, err)
	case errors.Is(err, service.ErrUnauthorized):
		s.writeError(w, http.StatusUnauthorized, err)
	case errors.Is(err, service.ErrRateLimited):
		s.writeError(w, http.StatusTooManyRequests, err)
	case errors.Is(err, storage.ErrNotFound):
		s.writeError(w, http.StatusNotFound, err)
	default:
		s.writeError(w, http.StatusInternalServerError, err)
	}
}

func (s *Server) writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func deviceIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(deviceIDKey).(string)
	return value
}

func requestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey).(string)
	return value
}

func clientKey(r *http.Request) string {
	host := r.Header.Get("X-Forwarded-For")
	if host != "" {
		return host
	}
	return r.RemoteAddr
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *statusRecorder) Write(payload []byte) (int, error) {
	size, err := r.ResponseWriter.Write(payload)
	r.bytes += size
	return size, err
}
