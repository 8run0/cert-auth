package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"
)

func GenerateNewKeys() (*rsa.PrivateKey, *rsa.PublicKey) {
	caPrivKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	return caPrivKey, &caPrivKey.PublicKey
}

func GenerateCARootCertificate(privKey *rsa.PrivateKey, pubKey *rsa.PublicKey) *x509.Certificate {
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(2021),
		Subject:               pkix.Name{CommonName: "server-bruno.org", Organization: []string{"server-bruno"}},
		DNSNames:              []string{"server-bruno.org"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, pubKey, privKey)
	if err != nil {
		log.Printf("failed to create certificate: %s ", err.Error())
	}
	cert, err := x509.ParseCertificate(caBytes)
	if err != nil {
		log.Printf("failed to parse certificate bytes: %s ", err.Error())
	}
	return cert
}

func SignCSRPemWithKeyAndCertificate(csr *x509.CertificateRequest, privKey *rsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	clientCRTTemplate := &x509.Certificate{
		SignatureAlgorithm: csr.SignatureAlgorithm,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,

		SerialNumber: big.NewInt(2),
		Issuer:       cert.Subject,
		Subject:      csr.Subject,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, clientCRTTemplate, cert, csr.PublicKey, privKey)
	if err != nil {
		log.Printf("failed to create certificate: %s ", err.Error())
		return nil, err
	}
	return pemEncode(certBytes, "CERTIFICATE"), nil
}
