package auth

import (
	"authorization-service/internal/domain/models"
	jwt "authorization-service/internal/lib/jwt"
	"authorization-service/internal/repository"
	"context"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log/slog"
	"time"
)

type Auth struct {
	log          *slog.Logger
	tokenTTL     time.Duration
	appProvider  AppProvider
	userProvider UserProvider
}

type UserProvider interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (uId int64, err error)
	User(ctx context.Context, email string) (user models.User, err error)
	IsAdmin(ctx context.Context, uId int64) (isAdmin bool, err error)
}

type AppProvider interface {
	App(ctx context.Context, appId int) (app models.App, err error)
}

func New(log *slog.Logger, userProvider UserProvider, appProvider AppProvider, tokenTTL time.Duration) *Auth {
	return &Auth{
		log:          log,
		userProvider: userProvider,
		appProvider:  appProvider,
		tokenTTL:     tokenTTL,
	}
}

var (
	InvalidCredentials   = errors.New("InvalidCredentials")
	ErrUserAlreadyExists = errors.New("UserAlreadyExists")
	ErrUserNotFound      = errors.New("UserNotFound")
)

func (a *Auth) Login(ctx context.Context, email, password string, appID int) (string, error) {
	const op = "auth.Login"

	log := a.log.With(slog.String("operation", op))

	log.Info("user is logging")

	user, err := a.userProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))
			return "", fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}

		log.Error("failed to save user", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)

	}

	err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password))
	if err != nil {
		log.Error("invalid password", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, InvalidCredentials)
	}

	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		if errors.Is(err, repository.ErrAppNotFound) {
			log.Warn("app not found", slog.String("error", err.Error()))
			return "", fmt.Errorf("%s: %w", op, InvalidCredentials)
		}
		log.Error("failed to load app", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		log.Error("failed to create token", slog.String("error", err.Error()))
		return "", fmt.Errorf("%s: %w", op, err)
	}

	return token, nil

}

func (a *Auth) RegisterNewUser(ctx context.Context, email, password string) (int64, error) {
	const op = "auth.RegisterNewUser"

	log := a.log.With(slog.String("operation", op))

	log.Info("registering new user")

	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", slog.String("error", err.Error()))

		return 0, fmt.Errorf("%s: %w", op, err)
	}

	id, err := a.userProvider.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, repository.ErrUserAlreadyExists) {
			log.Debug("user already exists", slog.String("error", err.Error()))
			return 0, fmt.Errorf("%s: %w", op, err)
		}
		log.Error("failed to save user", slog.String("error", err.Error()))
		return 0, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("user created")
	return id, nil
}

func (a *Auth) IsAdmin(ctx context.Context, uId int64) (bool, error) {
	const op = "auth.IsAdmin"

	log := a.log.With(slog.String("operation", op))

	log.Info("checking if user is admin")

	isAdmin, err := a.userProvider.IsAdmin(ctx, uId)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			log.Warn("user not found", slog.String("error", err.Error()))
			return false, fmt.Errorf("%s: %w", op, ErrUserNotFound)
		}
		log.Error("failed to check if user is admin", slog.String("error", err.Error()))
		return false, fmt.Errorf("%s: %w", op, err)
	}

	log.Info("checked user is admin")

	return isAdmin, nil
}
