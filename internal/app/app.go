package app

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"xam/linux_server/internal/auth"
	"xam/linux_server/internal/config"
	"xam/linux_server/internal/debuglog"
	"xam/linux_server/internal/httpapi"
	"xam/linux_server/internal/objectstore"
	"xam/linux_server/internal/push"
	"xam/linux_server/internal/service"
	"xam/linux_server/internal/storage"
)

type App struct {
	store   *storage.PostgresStore
	objects *objectstore.Client
	http    *httpapi.Server
	cancel  context.CancelFunc
}

func New(cfg config.Config, logger *slog.Logger) (*App, error) {
	store, err := storage.NewPostgresStore(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	if err := retry(context.Background(), 10, 2*time.Second, store.Ping); err != nil {
		_ = store.Close()
		return nil, err
	}

	objects, err := objectstore.New(cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3Bucket, cfg.S3UseSSL, cfg.PresignTTL)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := retry(context.Background(), 10, 2*time.Second, objects.EnsureBucket); err != nil {
		_ = store.Close()
		return nil, err
	}

	tokens := auth.NewTokenManager(cfg.JWTSecret, cfg.TokenTTL)
	logbook := debuglog.New(cfg.DebugLogBuffer)
	pushSender, err := push.New(cfg, logger)
	if err != nil {
		_ = store.Close()
		return nil, err
	}
	svc := service.New(cfg, store, objects, tokens, pushSender, logger, logbook)
	server := httpapi.New(cfg, logger, svc, tokens, logbook)

	ctx, cancel := context.WithCancel(context.Background())
	go svc.RunCleanupLoop(ctx)

	return &App{
		store:   store,
		objects: objects,
		http:    server,
		cancel:  cancel,
	}, nil
}

func (a *App) Router() http.Handler {
	return a.http.Router()
}

func (a *App) Close() {
	if a.cancel != nil {
		a.cancel()
	}
	if a.store != nil {
		_ = a.store.Close()
	}
}

func retry(ctx context.Context, attempts int, delay time.Duration, fn func(context.Context) error) error {
	var lastErr error
	for i := 0; i < attempts; i++ {
		if err := fn(ctx); err == nil {
			return nil
		} else {
			lastErr = err
		}
		if i < attempts-1 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	return fmt.Errorf("operation failed after %d attempts: %w", attempts, lastErr)
}
