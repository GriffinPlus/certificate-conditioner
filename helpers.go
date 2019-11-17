package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/youmark/pkcs8"

	"github.com/grantae/certinfo"
	log "github.com/sirupsen/logrus"
)

func isIssuerCertificate(certificate, issuerCertificate *x509.Certificate) (bool, error) {

	// check key ids, if available
	if len(certificate.AuthorityKeyId) > 0 {
		if bytes.Equal(certificate.SubjectKeyId, issuerCertificate.AuthorityKeyId) {
			return false, nil
		}
	} else {
		if certificate.Issuer.String() != issuerCertificate.Subject.String() {
			return false, nil
		}
	}

	// check whether the certificate was signed using the issuer certificate
	err := certificate.CheckSignatureFrom(issuerCertificate)
	return err == nil, err
}

func isPrivateKeyToPublicKey(privateKey crypto.PrivateKey, publicKey crypto.PublicKey) (bool, error) {

	// marshal specified public key to compare it with the public key the private key brings along
	buf1, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return false, err
	}

	var buf2 []byte
	switch sk := privateKey.(type) {
	case *rsa.PrivateKey:
		buf2, err = x509.MarshalPKIXPublicKey(sk.Public())
		if err != nil {
			return false, err
		}
	case *ecdsa.PrivateKey:
		buf2, err = x509.MarshalPKIXPublicKey(sk.Public())
		if err != nil {
			return false, err
		}
	case *ed25519.PrivateKey:
		buf2, err = x509.MarshalPKIXPublicKey(sk.Public())
		if err != nil {
			return false, err
		}
	default:
		return false, fmt.Errorf("Private key type (%T) is not supported", privateKey)
	}

	return bytes.Equal(buf1, buf2), nil
}

func printCertificate(certificate *x509.Certificate, message string) {

	if log.IsLevelEnabled(log.DebugLevel) {
		result, err := certinfo.CertificateText(certificate)
		if err != nil {
			log.Errorf("Printing certificate failed: %s", err)
			return
		}
		log.Debug(message, "\n", result)
	}
}

func splitCertificatesByCategory(certificates []*x509.Certificate) ([]*x509.Certificate, []*x509.Certificate) {
	var endEntityCertificates []*x509.Certificate
	var caCertificates []*x509.Certificate
	for _, certificate := range certificates {
		if certificate.BasicConstraintsValid && certificate.IsCA {
			caCertificates = append(caCertificates, certificate)
		} else {
			endEntityCertificates = append(endEntityCertificates, certificate)
		}
	}
	return endEntityCertificates, caCertificates
}

func writePkcs1PrivateKeyDer(writer io.Writer, privateKey crypto.PrivateKey) error {

	// ensure that the specified key is an RSA private key (other algorithms are not supported by PKCS#1)
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("The private key is not a RSA private key")
	}

	// write private key
	privBytes := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	_, err := writer.Write(privBytes)
	return err
}

func writePkcs1PrivateKeyPem(writer io.Writer, privateKey crypto.PrivateKey, password string) error {

	// ensure that the specified key is an RSA private key (other algorithms are not supported by PKCS#1)
	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("The private key is not a RSA private key")
	}

	// write private key
	// (encryption occurs at the PEM level)
	privBytes := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
	var pemBlock *pem.Block
	var err error
	if len(password) > 0 {
		pemBlock, err = x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", privBytes, []byte(password), x509.PEMCipherAES256)
		if err != nil {
			return err
		}
	} else {
		pemBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	}

	// write PEM block to file
	if err := pem.Encode(writer, pemBlock); err != nil {
		return err
	}

	return nil
}

func writePkcs8PrivateKeyDer(writer io.Writer, privateKey crypto.PrivateKey, password string) error {

	// convert private key to PKCS#8 (supports RSA and ECDSA only)
	// (encryption occurs at the ASN.1 level)
	privBytes, err := pkcs8.ConvertPrivateKeyToPKCS8(privateKey, []byte(password))
	if err != nil {
		log.Errorf("Marshalling private key failed: %s", err)
		return err
	}

	// write private key
	_, err = writer.Write(privBytes)
	return err
}

func writePkcs8PrivateKeyPem(writer io.Writer, privateKey crypto.PrivateKey, password string) error {

	// convert private key to PKCS#8 (supports RSA and ECDSA only)
	// (encryption occurs at the ASN.1 level)
	privBytes, err := pkcs8.ConvertPrivateKeyToPKCS8(privateKey, []byte(password))
	if err != nil {
		log.Errorf("Marshalling private key failed: %s", err)
		return err
	}

	// determine the type of the PEM block to write
	var pemBlockType string
	if len(password) > 0 {
		pemBlockType = "ENCRYPTED PRIVATE KEY"
	} else {
		pemBlockType = "PRIVATE KEY"
	}

	// write PEM block
	if err := pem.Encode(writer, &pem.Block{Type: pemBlockType, Bytes: privBytes}); err != nil {
		return err
	}

	return nil
}
