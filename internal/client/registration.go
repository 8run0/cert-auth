package client

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"

	kllla "github.com/8run0/kllla/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	registrationServer     = ":50051"
	tokenServer            = ":50052"
	clientPrivKeyLocation  = "./keys/%s-key.pem"
	clientRootCertLocation = "./keys/%s-cert.pem"
)

func GetRegistrationCertificate() {
	log.Printf("connecting to registration server:%s ... ", registrationServer)
	conn, err := grpc.Dial(registrationServer, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	log.Printf("connected to registration server")
	regClient := kllla.NewRegistrationServiceClient(conn)

	resp, err := regClient.GetRegistrationCertificate(context.Background(), &kllla.GetRegistrationCertificateRequest{})
	if err != nil {
		log.Fatalf("failed to get registration certificate: %v", err)
	}
	log.Printf("registration certificate retrieved")
	err = ioutil.WriteFile("./keys/ca-cert.pem", resp.Cert, 0644)
	if err != nil {
		log.Fatalf("failed to get write certificate to file: %v", err)
	}
}

func RegisterNewName(name string) {
	log.Printf("connecting to registration server:%s ... ", registrationServer)
	conn, err := grpc.Dial(registrationServer, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	log.Printf("connected to registration server")
	regClient := kllla.NewRegistrationServiceClient(conn)
	privKey, csr := createCSRForNewKeyPair(name)
	resp, err := regClient.RequestCASignCSR(context.Background(), &kllla.RegistrationSignRequest{Name: name, Csr: csr})
	if err != nil {
		log.Fatalf("failed to get csr signed: %v", err)
	}
	log.Printf("registration %t, %s", resp.IsSigned, pemEncode(resp.Cert, "CERTIFICATE"))
	certPem, _ := pem.Decode(resp.Cert)
	if err != nil {
		log.Fatalf("failed to get decode cert: %v", err)
	}
	cert, err := x509.ParseCertificate(certPem.Bytes)
	if err != nil {
		log.Fatalf("failed to get parser cert: %v", err)
	}
	writePrivAndCertToFile(name, privKey, cert)
}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// Load certificate of the CA who signed server's certificate
	pemServerCA, err := ioutil.ReadFile("./keys/ca-cert.pem")
	if err != nil {
		return nil, err
	}

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(pemServerCA) {
		return nil, fmt.Errorf("failed to add server CA's certificate")
	}

	// Create the credentials and return it
	config := &tls.Config{
		RootCAs: certPool,
	}

	return credentials.NewTLS(config), nil
}

func NewTokenForKey(key string) {
	log.Printf("connecting to token server:%s ... ", tokenServer)
	tlsCredentials, err := loadTLSCredentials()
	if err != nil {
		log.Fatal("cannot load TLS credentials: ", err)
	}
	conn, err := grpc.Dial(tokenServer, grpc.WithTransportCredentials(tlsCredentials))
	if err != nil {
		log.Fatal("cannot dial server: ", err)
	}

	log.Printf("connected to token server")
	tokenClient := kllla.NewTokenServiceClient(conn)
	resp, err := tokenClient.InitTokenHandshake(context.Background(), &kllla.InitTokenHandshakeRequest{Name: "bruno"})
	if err != nil {
		log.Fatalf("failed to get init handshake: %v", err)
	}
	log.Printf("encrypted:  %s", resp.Encrypted)
}

func writePrivAndCertToFile(name string, privkey *rsa.PrivateKey, cert *x509.Certificate) error {
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privkey)})
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw})
	err := ioutil.WriteFile(fmt.Sprintf(clientPrivKeyLocation, name), keyPem, 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fmt.Sprintf(clientRootCertLocation, name), certPem, 0644)
	if err != nil {
		return err
	}
	return nil
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
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, clientPriv)
	if err != nil {
		log.Fatal(err)
	}
	return clientPriv, csrDER
}
