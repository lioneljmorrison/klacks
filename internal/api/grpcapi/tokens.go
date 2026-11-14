package grpcapi

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// ServiceTokens authenticates the services calling the gRPC API (S-31): each
// RPC must carry "authorization: Bearer <token>" metadata naming one of the
// configured tokens. A token identifies a trusted service, not a user; the
// service acts as the server's configured actor. Tokens should be long
// random secrets sent over TLS. Several may be configured, so a token can be
// rotated without downtime.
type ServiceTokens struct {
	hashes [][sha256.Size]byte
}

// NewServiceTokens returns an authenticator accepting any of tokens. At
// least one is required, and none may be empty.
func NewServiceTokens(tokens ...string) (*ServiceTokens, error) {
	if len(tokens) == 0 {
		return nil, errors.New("grpcapi: at least one service token is required")
	}
	s := &ServiceTokens{}
	for _, t := range tokens {
		if t == "" {
			return nil, errors.New("grpcapi: empty service token")
		}
		s.hashes = append(s.hashes, sha256.Sum256([]byte(t)))
	}
	return s, nil
}

// ServerOptions returns the unary and stream interceptors to pass to
// grpc.NewServer.
func (s *ServiceTokens) ServerOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(s.unary),
		grpc.ChainStreamInterceptor(s.stream),
	}
}

func (s *ServiceTokens) unary(ctx context.Context, req any, _ *grpc.UnaryServerInfo, h grpc.UnaryHandler) (any, error) {
	if err := s.check(ctx); err != nil {
		return nil, err
	}
	return h(ctx, req)
}

func (s *ServiceTokens) stream(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
	if err := s.check(ss.Context()); err != nil {
		return err
	}
	return h(srv, ss)
}

func (s *ServiceTokens) check(ctx context.Context) error {
	md, _ := metadata.FromIncomingContext(ctx)
	for _, v := range md.Get("authorization") {
		scheme, tok, ok := strings.Cut(v, " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
			continue
		}
		// Compare fixed-size hashes in constant time, against every
		// configured token, so timing reveals neither length nor which.
		h := sha256.Sum256([]byte(tok))
		match := 0
		for i := range s.hashes {
			match |= subtle.ConstantTimeCompare(h[:], s.hashes[i][:])
		}
		if match == 1 {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "missing or invalid service token")
}
