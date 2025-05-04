package token_test

import (
	"authorization-service/internal/domain/models"
	jwt2 "authorization-service/internal/lib/jwt"
	"github.com/golang-jwt/jwt/v5"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewToken(t *testing.T) {
	user := models.User{ID: 1, Email: "test@example.com"}
	app := models.App{ID: 123, Secret: "supersecret"}
	duration := time.Hour

	tokenString, err := jwt2.NewToken(user, app, duration)
	require.NoError(t, err)
	require.NotEmpty(t, tokenString)

	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		require.Equal(t, jwt.SigningMethodHS256, token.Method)
		return []byte(app.Secret), nil
	})
	require.NoError(t, err)
	require.True(t, parsedToken.Valid)

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	require.True(t, ok)

	require.Equal(t, float64(user.ID), claims["uid"])
	require.Equal(t, user.Email, claims["email"])
	require.Equal(t, float64(app.ID), claims["appid"])

	exp, ok := claims["exp"].(float64)
	require.True(t, ok)
	require.True(t, time.Unix(int64(exp), 0).After(time.Now()))
}

func TestNewToken_EmptySecret(t *testing.T) {
	user := models.User{ID: 1, Email: "a@b.c"}
	app := models.App{ID: 123, Name: "test", Secret: ""}

	_, err := jwt2.NewToken(user, app, time.Hour)
	require.Error(t, err)
}
