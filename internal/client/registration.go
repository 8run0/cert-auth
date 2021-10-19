package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"

	kllla "github.com/8run0/kllla/pkg/pb"
	"google.golang.org/grpc"
)

const registrationServer = ":50051"

func RegisterNewName(name string) {
	log.Printf("connecting to registration server:%s ... ", registrationServer)
	conn, err := grpc.Dial(registrationServer, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	log.Printf("connected to registration server")
	regClient := kllla.NewRegistrationServiceClient(conn)
	_, csr := createCSRForNewKeyPair(name)
	resp, err := regClient.RequestCASignCSR(context.Background(), &kllla.RegistrationSignRequest{Name: name, Csr: csr})
	if err != nil {
		log.Fatalf("failed to get csr signed: %v", err)
	}
	log.Printf("registration %t, %s", resp.IsSigned, pemEncode(resp.Cert, "CERTIFICATE"))
}

func pemEncode(b []byte, t string) []byte {
	return pem.EncodeToMemory(&pem.Block{Bytes: b, Type: t})
}

func createCSRForNewKeyPair(name string) (*rsa.PrivateKey, []byte) {
	clientPriv, _ := rsa.GenerateKey(rand.Reader, 4096)
	template := &x509.CertificateRequest{
		SignatureAlgorithm: x509.SHA256WithRSA,
		PublicKeyAlgorithm: x509.RSA,
		PublicKey:          &clientPriv.PublicKey,
		Subject:            pkix.Name{CommonName: name},
		DNSNames:           []string{name},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, clientPriv)
	if err != nil {
		log.Fatal(err)
	}
	return clientPriv, csrDER
}
