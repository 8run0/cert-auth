package service

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
)

type RegistrationService interface {
	GetRegistrationCertificatePEM() []byte
	SignCSRPem(csrBytes []byte) ([]byte, error)
}

type registrationServiceImpl struct {
	ca *certificateAuthority
}

type certificateAuthority struct {
	registrationCertPEM []byte
	caPrivateKey        *rsa.PrivateKey
	caPublicKey         *rsa.PublicKey
	caRootCertificate   *x509.Certificate
}

func NewRegistrationService() RegistrationService {
	return setupCertificateAuthority()
}

func (rs *registrationServiceImpl) GetRegistrationCertificatePEM() []byte {
	return rs.ca.registrationCertPEM
}

// func main() {
// 	reg := NewRegistration()
// 	_, csr := createCSRForNewKeyPair()
// 	signedCert, _ := reg.SignCSR(csr)
// 	certs := x509.NewCertPool()
// 	certs.AddCert(reg.ca.caRootCertificate)
// 	opts := x509.VerifyOptions{
// 		Roots:   certs,
// 		DNSName: "bruno.org",
// 	}
// 	certChain, err := signedCert.Verify(opts)
// 	if err != nil {
// 		log.Printf("failed to verify certificate: " + err.Error())
// 	}
// 	log.Printf("certs have been verified: %v", certChain)
// }

const (
	caPrivKeyLocation  = "./keys/capriv.pem"
	caRootCertLocation = "./keys/caroot.pem"
)

func checkForExistingRoot() (*rsa.PrivateKey, *rsa.PublicKey, *x509.Certificate, error) {
	rootKeyPem, err := ioutil.ReadFile(caPrivKeyLocation)
	if err != nil {
		return nil, nil, nil, err
	}
	privPem, _ := pem.Decode(rootKeyPem)
	rootKey, err := x509.ParsePKCS1PrivateKey(privPem.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}

	rootCertPem, err := ioutil.ReadFile(caRootCertLocation)
	if err != nil {
		return nil, nil, nil, err
	}
	rootPem, _ := pem.Decode(rootCertPem)
	rootCert, err := x509.ParseCertificate(rootPem.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return rootKey, &rootKey.PublicKey, rootCert, nil
}

func setupCertificateAuthority() *registrationServiceImpl {
	caPrivKey, caPubKey, caRootCert, err := checkForExistingRoot()
	if err == nil {
		log.Printf("existing keys found")
		regPem := pemEncode(caRootCert.Raw, "CERTIFICATE")
		return &registrationServiceImpl{ca: &certificateAuthority{
			caPrivateKey:        caPrivKey,
			caPublicKey:         caPubKey,
			caRootCertificate:   caRootCert,
			registrationCertPEM: regPem,
		}}
	}
	log.Printf("generating new keys... %v", err)
	caPrivKey, caPubKey = GenerateNewKeys()
	caRootCert = GenerateCARootCertificate(caPrivKey, caPubKey)
	log.Print("saving new root to file")
	err = writePrivAndCertToFile(caPrivKey, caRootCert)
	if err != nil {
		log.Printf("failed to save files to disc: %v", err)
	}
	regPem := pemEncode(caRootCert.Raw, "CERTIFICATE")
	return &registrationServiceImpl{ca: &certificateAuthority{
		caPrivateKey:        caPrivKey,
		caPublicKey:         caPubKey,
		caRootCertificate:   caRootCert,
		registrationCertPEM: regPem,
	}}
}

func writePrivAndCertToFile(privkey *rsa.PrivateKey, cert *x509.Certificate) error {
	keyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privkey)})
	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw})
	err := ioutil.WriteFile(caPrivKeyLocation, keyPem, 0644)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(caRootCertLocation, certPem, 0644)
	if err != nil {
		return err
	}
	return nil
}

// func createCSRForNewKeyPair() (*rsa.PrivateKey, *x509.CertificateRequest) {
// 	clientPriv, clientPub := generateNewKeys()
// 	template := &x509.CertificateRequest{
// 		SignatureAlgorithm: x509.SHA256WithRSA,
// 		PublicKeyAlgorithm: x509.RSA,
// 		PublicKey:          clientPub,
// 		Subject:            pkix.Name{CommonName: "bruno.org"},
// 		DNSNames:           []string{"bruno.org"},
// 	}
// 	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, clientPriv)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	csr, err := x509.ParseCertificateRequest(csrDER)
// 	if err != nil {
// 		log.Printf("failed to parse certificate: %s ", err.Error())
// 	}
// 	return clientPriv, csr
// }

func pemEncode(b []byte, t string) []byte {
	return pem.EncodeToMemory(&pem.Block{Bytes: b, Type: t})
}

func (reg *registrationServiceImpl) SignCSRPem(csrBytes []byte) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}
	return SignCSRPemWithKeyAndCertificate(csr, reg.ca.caPrivateKey, reg.ca.caRootCertificate)
}
