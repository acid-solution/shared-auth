package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/LeoninCS/shared-auth/internal/auth"
	"github.com/LeoninCS/shared-auth/internal/config"
	"github.com/LeoninCS/shared-auth/internal/httpapi"
	"github.com/LeoninCS/shared-auth/internal/password"
	"github.com/LeoninCS/shared-auth/internal/storage/postgres"
	"github.com/LeoninCS/shared-auth/internal/storage/postgres/migrations"
	"github.com/LeoninCS/shared-auth/internal/token"
	"github.com/LeoninCS/shared-auth/internal/verification"
	"github.com/pressly/goose/v3"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
	if err := run(); err != nil {
		slog.Error("shared-auth stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	configuration, err := config.Load()
	if err != nil {
		return err
	}
	startupContext, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelStartup()
	database, err := postgres.Open(startupContext, configuration.DatabaseURL)
	if err != nil {
		return err
	}
	defer database.Close()

	goose.SetBaseFS(migrations.Files)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	if err := goose.Up(database, "sql"); err != nil {
		return err
	}
	repository := postgres.NewRepository(database)
	if err := repository.ReplaceClientOrigins(startupContext, "jobpilot", configuration.JobPilotAllowedOrigins); err != nil {
		return err
	}
	if err := repository.ReplaceClientOrigins(startupContext, "studyflow", configuration.StudyFlowAllowedOrigins); err != nil {
		return err
	}

	tokenManager, err := token.LoadManager(configuration.JWTPrivateKeyPath, configuration.JWTKeyID, configuration.JWTIssuer, configuration.AccessTokenTTL)
	if err != nil {
		return err
	}
	var sender verification.Sender
	var outbox *verification.DevOutbox
	switch configuration.EmailProvider {
	case "dev":
		outbox = verification.NewDevOutbox()
		sender = outbox
	case "resend":
		sender, err = verification.NewResendSender(configuration.ResendAPIKey, configuration.ResendFrom, nil)
		if err != nil {
			return err
		}
	default:
		return errors.New("unsupported email provider")
	}
	service, err := auth.NewService(
		repository, password.NewHasher(configuration.BcryptCost), tokenManager, sender,
		configuration.VerificationHMACKey, configuration.VerificationTTL, configuration.RefreshTokenTTL,
	)
	if err != nil {
		return err
	}

	allowedOrigins := append([]string{}, configuration.JobPilotAllowedOrigins...)
	allowedOrigins = append(allowedOrigins, configuration.StudyFlowAllowedOrigins...)
	router := httpapi.NewRouter(httpapi.Dependencies{
		Application: service, Outbox: outbox, CookieSecure: configuration.CookieSecure,
		AllowedOrigins: allowedOrigins,
		Ready: func() error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			return database.PingContext(ctx)
		},
	})
	server := &http.Server{
		Addr: configuration.HTTPAddr, Handler: router,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
	serverError := make(chan error, 1)
	go func() {
		slog.Info("shared-auth listening", "address", configuration.HTTPAddr, "environment", configuration.Environment)
		serverError <- server.ListenAndServe()
	}()

	shutdownSignal, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-shutdownSignal.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	case err := <-serverError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
