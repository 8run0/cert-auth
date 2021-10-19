// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package __

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// RegistrationServiceClient is the client API for RegistrationService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type RegistrationServiceClient interface {
	GetRegistrationCertificate(ctx context.Context, in *GetRegistrationCertificateRequest, opts ...grpc.CallOption) (*GetRegistrationCertificateResponse, error)
	RequestCASignCSR(ctx context.Context, in *RegistrationSignRequest, opts ...grpc.CallOption) (*RegistrationSignResponse, error)
}

type registrationServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewRegistrationServiceClient(cc grpc.ClientConnInterface) RegistrationServiceClient {
	return &registrationServiceClient{cc}
}

func (c *registrationServiceClient) GetRegistrationCertificate(ctx context.Context, in *GetRegistrationCertificateRequest, opts ...grpc.CallOption) (*GetRegistrationCertificateResponse, error) {
	out := new(GetRegistrationCertificateResponse)
	err := c.cc.Invoke(ctx, "/kllla.RegistrationService/GetRegistrationCertificate", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *registrationServiceClient) RequestCASignCSR(ctx context.Context, in *RegistrationSignRequest, opts ...grpc.CallOption) (*RegistrationSignResponse, error) {
	out := new(RegistrationSignResponse)
	err := c.cc.Invoke(ctx, "/kllla.RegistrationService/RequestCASignCSR", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RegistrationServiceServer is the server API for RegistrationService service.
// All implementations must embed UnimplementedRegistrationServiceServer
// for forward compatibility
type RegistrationServiceServer interface {
	GetRegistrationCertificate(context.Context, *GetRegistrationCertificateRequest) (*GetRegistrationCertificateResponse, error)
	RequestCASignCSR(context.Context, *RegistrationSignRequest) (*RegistrationSignResponse, error)
	mustEmbedUnimplementedRegistrationServiceServer()
}

// UnimplementedRegistrationServiceServer must be embedded to have forward compatible implementations.
type UnimplementedRegistrationServiceServer struct {
}

func (UnimplementedRegistrationServiceServer) GetRegistrationCertificate(context.Context, *GetRegistrationCertificateRequest) (*GetRegistrationCertificateResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetRegistrationCertificate not implemented")
}
func (UnimplementedRegistrationServiceServer) RequestCASignCSR(context.Context, *RegistrationSignRequest) (*RegistrationSignResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RequestCASignCSR not implemented")
}
func (UnimplementedRegistrationServiceServer) mustEmbedUnimplementedRegistrationServiceServer() {}

// UnsafeRegistrationServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to RegistrationServiceServer will
// result in compilation errors.
type UnsafeRegistrationServiceServer interface {
	mustEmbedUnimplementedRegistrationServiceServer()
}

func RegisterRegistrationServiceServer(s grpc.ServiceRegistrar, srv RegistrationServiceServer) {
	s.RegisterService(&RegistrationService_ServiceDesc, srv)
}

func _RegistrationService_GetRegistrationCertificate_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetRegistrationCertificateRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationServiceServer).GetRegistrationCertificate(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kllla.RegistrationService/GetRegistrationCertificate",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationServiceServer).GetRegistrationCertificate(ctx, req.(*GetRegistrationCertificateRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _RegistrationService_RequestCASignCSR_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegistrationSignRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(RegistrationServiceServer).RequestCASignCSR(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kllla.RegistrationService/RequestCASignCSR",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(RegistrationServiceServer).RequestCASignCSR(ctx, req.(*RegistrationSignRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// RegistrationService_ServiceDesc is the grpc.ServiceDesc for RegistrationService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var RegistrationService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kllla.RegistrationService",
	HandlerType: (*RegistrationServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetRegistrationCertificate",
			Handler:    _RegistrationService_GetRegistrationCertificate_Handler,
		},
		{
			MethodName: "RequestCASignCSR",
			Handler:    _RegistrationService_RequestCASignCSR_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kllla.proto",
}

// TokenServiceClient is the client API for TokenService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type TokenServiceClient interface {
	InitTokenHandshake(ctx context.Context, in *InitTokenHandshakeRequest, opts ...grpc.CallOption) (*InitTokenHandshakeResponse, error)
	CompleteTokenHandshake(ctx context.Context, in *CompleteTokenRequest, opts ...grpc.CallOption) (*CompleteTokenResponse, error)
	IsTokenValid(ctx context.Context, in *IsTokenValidRequest, opts ...grpc.CallOption) (*IsTokenValidResponse, error)
}

type tokenServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewTokenServiceClient(cc grpc.ClientConnInterface) TokenServiceClient {
	return &tokenServiceClient{cc}
}

func (c *tokenServiceClient) InitTokenHandshake(ctx context.Context, in *InitTokenHandshakeRequest, opts ...grpc.CallOption) (*InitTokenHandshakeResponse, error) {
	out := new(InitTokenHandshakeResponse)
	err := c.cc.Invoke(ctx, "/kllla.TokenService/InitTokenHandshake", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokenServiceClient) CompleteTokenHandshake(ctx context.Context, in *CompleteTokenRequest, opts ...grpc.CallOption) (*CompleteTokenResponse, error) {
	out := new(CompleteTokenResponse)
	err := c.cc.Invoke(ctx, "/kllla.TokenService/CompleteTokenHandshake", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokenServiceClient) IsTokenValid(ctx context.Context, in *IsTokenValidRequest, opts ...grpc.CallOption) (*IsTokenValidResponse, error) {
	out := new(IsTokenValidResponse)
	err := c.cc.Invoke(ctx, "/kllla.TokenService/IsTokenValid", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TokenServiceServer is the server API for TokenService service.
// All implementations must embed UnimplementedTokenServiceServer
// for forward compatibility
type TokenServiceServer interface {
	InitTokenHandshake(context.Context, *InitTokenHandshakeRequest) (*InitTokenHandshakeResponse, error)
	CompleteTokenHandshake(context.Context, *CompleteTokenRequest) (*CompleteTokenResponse, error)
	IsTokenValid(context.Context, *IsTokenValidRequest) (*IsTokenValidResponse, error)
	mustEmbedUnimplementedTokenServiceServer()
}

// UnimplementedTokenServiceServer must be embedded to have forward compatible implementations.
type UnimplementedTokenServiceServer struct {
}

func (UnimplementedTokenServiceServer) InitTokenHandshake(context.Context, *InitTokenHandshakeRequest) (*InitTokenHandshakeResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method InitTokenHandshake not implemented")
}
func (UnimplementedTokenServiceServer) CompleteTokenHandshake(context.Context, *CompleteTokenRequest) (*CompleteTokenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CompleteTokenHandshake not implemented")
}
func (UnimplementedTokenServiceServer) IsTokenValid(context.Context, *IsTokenValidRequest) (*IsTokenValidResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsTokenValid not implemented")
}
func (UnimplementedTokenServiceServer) mustEmbedUnimplementedTokenServiceServer() {}

// UnsafeTokenServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to TokenServiceServer will
// result in compilation errors.
type UnsafeTokenServiceServer interface {
	mustEmbedUnimplementedTokenServiceServer()
}

func RegisterTokenServiceServer(s grpc.ServiceRegistrar, srv TokenServiceServer) {
	s.RegisterService(&TokenService_ServiceDesc, srv)
}

func _TokenService_InitTokenHandshake_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InitTokenHandshakeRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokenServiceServer).InitTokenHandshake(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kllla.TokenService/InitTokenHandshake",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokenServiceServer).InitTokenHandshake(ctx, req.(*InitTokenHandshakeRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TokenService_CompleteTokenHandshake_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CompleteTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokenServiceServer).CompleteTokenHandshake(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kllla.TokenService/CompleteTokenHandshake",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokenServiceServer).CompleteTokenHandshake(ctx, req.(*CompleteTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _TokenService_IsTokenValid_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IsTokenValidRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokenServiceServer).IsTokenValid(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kllla.TokenService/IsTokenValid",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokenServiceServer).IsTokenValid(ctx, req.(*IsTokenValidRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// TokenService_ServiceDesc is the grpc.ServiceDesc for TokenService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var TokenService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kllla.TokenService",
	HandlerType: (*TokenServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "InitTokenHandshake",
			Handler:    _TokenService_InitTokenHandshake_Handler,
		},
		{
			MethodName: "CompleteTokenHandshake",
			Handler:    _TokenService_CompleteTokenHandshake_Handler,
		},
		{
			MethodName: "IsTokenValid",
			Handler:    _TokenService_IsTokenValid_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kllla.proto",
}

// ShortenServiceClient is the client API for ShortenService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ShortenServiceClient interface {
	Shorten(ctx context.Context, in *ShortenRequest, opts ...grpc.CallOption) (*ShortenResponse, error)
}

type shortenServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewShortenServiceClient(cc grpc.ClientConnInterface) ShortenServiceClient {
	return &shortenServiceClient{cc}
}

func (c *shortenServiceClient) Shorten(ctx context.Context, in *ShortenRequest, opts ...grpc.CallOption) (*ShortenResponse, error) {
	out := new(ShortenResponse)
	err := c.cc.Invoke(ctx, "/kllla.ShortenService/Shorten", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ShortenServiceServer is the server API for ShortenService service.
// All implementations must embed UnimplementedShortenServiceServer
// for forward compatibility
type ShortenServiceServer interface {
	Shorten(context.Context, *ShortenRequest) (*ShortenResponse, error)
	mustEmbedUnimplementedShortenServiceServer()
}

// UnimplementedShortenServiceServer must be embedded to have forward compatible implementations.
type UnimplementedShortenServiceServer struct {
}

func (UnimplementedShortenServiceServer) Shorten(context.Context, *ShortenRequest) (*ShortenResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Shorten not implemented")
}
func (UnimplementedShortenServiceServer) mustEmbedUnimplementedShortenServiceServer() {}

// UnsafeShortenServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ShortenServiceServer will
// result in compilation errors.
type UnsafeShortenServiceServer interface {
	mustEmbedUnimplementedShortenServiceServer()
}

func RegisterShortenServiceServer(s grpc.ServiceRegistrar, srv ShortenServiceServer) {
	s.RegisterService(&ShortenService_ServiceDesc, srv)
}

func _ShortenService_Shorten_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ShortenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ShortenServiceServer).Shorten(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/kllla.ShortenService/Shorten",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ShortenServiceServer).Shorten(ctx, req.(*ShortenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// ShortenService_ServiceDesc is the grpc.ServiceDesc for ShortenService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ShortenService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "kllla.ShortenService",
	HandlerType: (*ShortenServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Shorten",
			Handler:    _ShortenService_Shorten_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "kllla.proto",
}