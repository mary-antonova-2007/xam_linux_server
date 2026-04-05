package config

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddress        string
	DatabaseURL        string
	JWTSecret          string
	TokenTTL           time.Duration
	ChallengeTTL       time.Duration
	MessageTTL         time.Duration
	CleanupInterval    time.Duration
	PullLimitDefault   int
	PullLimitMax       int
	MaxCiphertextBytes int
	MaxAttachmentBytes int64
	MaxACKItems        int
	AuthRatePerMinute  int
	SendRatePerMinute  int
	PullRatePerMinute  int
	S3Endpoint         string
	S3AccessKey        string
	S3SecretKey        string
	S3Bucket           string
	S3UseSSL           bool
	PresignTTL         time.Duration
	LogLevel           slog.Level
	DebugAPIEnabled    bool
	DebugLogBuffer     int
	FCMProjectID       string
	FCMCredentialsJSON string
	FCMCredentialsFile string
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddress:        getEnv("HTTP_ADDRESS", ":8080"),
		DatabaseURL:        getEnv("DATABASE_URL", "postgres://messenger:messenger@postgres:5432/messenger?sslmode=disable"),
		JWTSecret:          getEnv("JWT_SECRET", "change-me-in-production"),
		TokenTTL:           getDurationEnv("TOKEN_TTL", 24*time.Hour),
		ChallengeTTL:       getDurationEnv("CHALLENGE_TTL", 5*time.Minute),
		MessageTTL:         getDurationEnv("MESSAGE_TTL", 30*24*time.Hour),
		CleanupInterval:    getDurationEnv("CLEANUP_INTERVAL", 10*time.Minute),
		PullLimitDefault:   getIntEnv("PULL_LIMIT_DEFAULT", 50),
		PullLimitMax:       getIntEnv("PULL_LIMIT_MAX", 200),
		MaxCiphertextBytes: getIntEnv("MAX_CIPHERTEXT_BYTES", 1024*1024),
		MaxAttachmentBytes: getInt64Env("MAX_ATTACHMENT_BYTES", 100*1024*1024),
		MaxACKItems:        getIntEnv("MAX_ACK_ITEMS", 500),
		AuthRatePerMinute:  getIntEnv("RATE_AUTH_PER_MINUTE", 30),
		SendRatePerMinute:  getIntEnv("RATE_SEND_PER_MINUTE", 120),
		PullRatePerMinute:  getIntEnv("RATE_PULL_PER_MINUTE", 240),
		S3Endpoint:         getEnv("S3_ENDPOINT", "minio:9000"),
		S3AccessKey:        getEnv("S3_ACCESS_KEY", "minioadmin"),
		S3SecretKey:        getEnv("S3_SECRET_KEY", "minioadmin"),
		S3Bucket:           getEnv("S3_BUCKET", "messenger"),
		S3UseSSL:           getBoolEnv("S3_USE_SSL", false),
		PresignTTL:         getDurationEnv("PRESIGN_TTL", 15*time.Minute),
		LogLevel:           getLogLevel(getEnv("LOG_LEVEL", "INFO")),
		DebugAPIEnabled:    getBoolEnv("DEBUG_API_ENABLED", false),
		DebugLogBuffer:     getIntEnv("DEBUG_LOG_BUFFER", 500),
		FCMProjectID:       getEnv("FCM_PROJECT_ID", ""),
		FCMCredentialsJSON: getEnv("FCM_CREDENTIALS_JSON", ""),
		FCMCredentialsFile: getEnv("FCM_CREDENTIALS_FILE", ""),
	}

	if cfg.JWTSecret == "" {
		return Config{}, fmt.Errorf("JWT_SECRET is required")
	}
	if cfg.PullLimitDefault <= 0 || cfg.PullLimitMax <= 0 || cfg.PullLimitDefault > cfg.PullLimitMax {
		return Config{}, fmt.Errorf("invalid pull limits")
	}
	return cfg, nil
}

func getEnv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func getIntEnv(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getInt64Env(key string, fallback int64) int64 {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func getBoolEnv(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getDurationEnv(key string, fallback time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func getLogLevel(value string) slog.Level {
	switch value {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
