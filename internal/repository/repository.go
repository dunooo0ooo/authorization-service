package repository

import "errors"

var (
	ErrUserAlreadyExists = errors.New("UserAlreadyExists")
	ErrUserNotFound      = errors.New("UserNotFound")
	ErrAppNotFound       = errors.New("AppNotFound")
)
