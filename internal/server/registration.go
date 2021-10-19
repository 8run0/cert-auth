package server

import (
	"context"
	"log"
	"net"

	"github.com/8run0/kllla/internal/service"
	kllla "github.com/8run0/kllla/pkg/pb"
	"google.golang.org/grpc"
)

const (
	PORT = ":50051"
)

type RegistrationServer struct {
	kllla.UnimplementedRegistrationServiceServer
	registrationService service.RegistrationService
}

func NewRegistration() *RegistrationServer {
	return &RegistrationServer{registrationService: service.NewRegistrationService()}
}

func (rs *RegistrationServer) GetRegistrationCertificate(ctx context.Context, req *kllla.GetRegistrationCertificateRequest) (res *kllla.GetRegistrationCertificateResponse, err error) {
	return &kllla.GetRegistrationCertificateResponse{
		Cert: rs.registrationService.GetRegistrationCertificatePEM()}, nil
}
func (rs *RegistrationServer) RequestCASignCSR(ctx context.Context, req *kllla.RegistrationSignRequest) (res *kllla.RegistrationSignResponse, err error) {
	signedCert, err := rs.registrationService.SignCSRPem(req.Csr)
	if err != nil {
		return nil, err
	}
	log.Printf("registered new user %v", req.Name)
	return &kllla.RegistrationSignResponse{Cert: signedCert,
		IsSigned: true}, nil
}

func (rs *RegistrationServer) ListenAndServe() {
	rs.serve(rs.listen())
}
func (rs *RegistrationServer) listen() net.Listener {
	lis, err := net.Listen("tcp", PORT)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("kllla registration service listening at %v", lis.Addr())
	return lis
}

func (rs *RegistrationServer) serve(lis net.Listener) {
	svr := grpc.NewServer()
	kllla.RegisterRegistrationServiceServer(svr, rs)
	if err := svr.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
