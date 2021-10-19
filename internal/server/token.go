package server

import (
	"context"
	"crypto/tls"
	"log"
	"net"

	"github.com/8run0/kllla/internal/service"
	kllla "github.com/8run0/kllla/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	TOKENPORT = ":50052"
)

type TokenServer struct {
	kllla.UnimplementedTokenServiceServer
	tokenService service.TokenService
}

func NewTokenServer() *TokenServer {
	return &TokenServer{tokenService: service.NewTokenService()}
}

func (ts *TokenServer) InitTokenHandshake(ctx context.Context, req *kllla.InitTokenHandshakeRequest) (res *kllla.InitTokenHandshakeResponse, err error) {
	token, err := ts.tokenService.NewTokenForKey(req.Name)
	if err != nil {
		return nil, err
	}
	log.Printf("token %v generated for key: %v ", token, req.Name)
	return &kllla.InitTokenHandshakeResponse{Encrypted: token}, nil
}

func (ts *TokenServer) CompleteTokenHandshake(ctx context.Context, req *kllla.CompleteTokenRequest) (res *kllla.CompleteTokenResponse, err error) {
	return nil, status.Errorf(codes.Unimplemented, "method CompleteTokenHandshake not implemented")
}
func (ts *TokenServer) IsTokenValid(xtx context.Context, req *kllla.IsTokenValidRequest) (res *kllla.IsTokenValidResponse, err error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsTokenValid not implemented")
}

func (ts *TokenServer) ListenAndServe() {
	ts.serve(ts.listen())
}
func (ts *TokenServer) listen() net.Listener {
	lis, err := net.Listen("tcp", TOKENPORT)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("kllla token service listening at %v", lis.Addr())
	return lis
}

func (ts *TokenServer) serve(lis net.Listener) {
	tlsCredentials, err := loadTLSCredentials()
	if err != nil {
		log.Fatal("cannot load TLS credentials: ", err)
	}

	svr := grpc.NewServer(
		grpc.Creds(tlsCredentials),
	)
	kllla.RegisterTokenServiceServer(svr, ts)
	if err := svr.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}

}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load server's certificate and private key
	serverCert, err := tls.LoadX509KeyPair("./keys/token-svr-cert.pem", "./keys/token-svr-key.pem")
	if err != nil {
		return nil, err
	}

	// Create the credentials and return it
	config := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	return credentials.NewTLS(config), nil
}
