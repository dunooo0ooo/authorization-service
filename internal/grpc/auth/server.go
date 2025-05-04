package auth

import (
	"authorization-service/internal/services/auth"
	proto "authorization-service/protos/gen/go/protos"
	"context"
	"errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(ctx context.Context, email, password string, appID int) (string, error)
	RegisterNewUser(ctx context.Context, email, password string) (int64, error)
	IsAdmin(ctx context.Context, userId int64) (bool, error)
}

const (
	emptyString = ""
	emptyValue  = 0
)

type serverAPI struct {
	proto.UnimplementedAuthServer
	auth Auth
}

func Register(gRPC *grpc.Server, auth Auth) {
	proto.RegisterAuthServer(gRPC, &serverAPI{auth: auth})
}

func (s *serverAPI) Login(ctx context.Context, req *proto.LoginRequest) (*proto.LoginResponse, error) {
	if req.GetEmail() == emptyString {
		return nil, status.Error(codes.InvalidArgument, "login requires email and password")
	}

	if req.GetPassword() == emptyString {
		return nil, status.Error(codes.InvalidArgument, "login requires password")
	}

	if req.GetAppId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "login requires app id")
	}

	token, err := s.auth.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, auth.InvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &proto.LoginResponse{
		Token: token,
	}, nil

}

func (s *serverAPI) Register(ctx context.Context, req *proto.RegisterRequest) (*proto.RegisterResponse, error) {
	if req.GetEmail() == emptyString {
		return nil, status.Error(codes.InvalidArgument, "login requires email")
	}

	if req.GetPassword() == emptyString {
		return nil, status.Error(codes.InvalidArgument, "login requires password")
	}

	userId, err := s.auth.RegisterNewUser(ctx, req.GetEmail(), req.GetPassword())
	if err != nil {
		if errors.Is(err, auth.ErrUserAlreadyExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &proto.RegisterResponse{
		UserId: userId,
	}, nil
}

func (s *serverAPI) IsAdmin(ctx context.Context, req *proto.IsAdminRequest) (*proto.IsAdminResponse, error) {
	if req.GetUserId() == emptyValue {
		return nil, status.Error(codes.InvalidArgument, "login requires user id")
	}

	isAdmin, err := s.auth.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}

	return &proto.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil

}
