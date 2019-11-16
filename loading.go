package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/mozilla-services/pkcs7"
	log "github.com/sirupsen/logrus"
	"github.com/youmark/pkcs8"
	"software.sslmate.com/src/go-pkcs12"
)

func loadCertificatesAndPrivateKeys(files []string, passwords []string) ([]*x509.Certificate, []crypto.PrivateKey, error) {

	allCertificates := []*x509.Certificate{}
	allPrivateKeys := []crypto.PrivateKey{}
	for _, path := range files {

		// read file
		log.Debugf("Reading file (%s)...", path)
		data, err := ioutil.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				log.Errorf("The specified file (%s) does not exist.", path)
				return nil, nil, fmt.Errorf("The specified file (%s) does not exist", path)
			}
			log.Errorf("Reading the specified file (%s) failed: %s", path, err)
			return nil, nil, fmt.Errorf("Reading the specified file (%s) failed: %s", path, err)
		}

		// try to parse file
		log.Debugf("Processing file (%s)...", path)
		certs, keys, err := parseCertificatesOrPrivateKeys(data, passwords)
		if err != nil {
			log.Errorf("Parsing file (%s) failed: %s", path, err)
			return nil, nil, fmt.Errorf("Parsing file (%s) failed: %s", path, err)
		}

		// print certificates
		for i, cert := range certs {
			printCertificate(cert, fmt.Sprintf("Parsing certificate (%d/%d) in file (%s) succeeded...", i+1, len(certs), path))
		}

		allCertificates = append(allCertificates, certs...)
		allPrivateKeys = append(allPrivateKeys, keys...)
	}

	return allCertificates, allPrivateKeys, nil
}

func parseCertificatesOrPrivateKeys(data []byte, passwords []string) ([]*x509.Certificate, []crypto.PrivateKey, error) {

	var certificates []*x509.Certificate
	var privateKeys []crypto.PrivateKey

	// try to parse data as DER encoded certificates
	// (the DER encoded certificates must be concatened without any space in between)
	certs, err := x509.ParseCertificates(data)
	if err == nil {
		return certs, privateKeys, nil
	}

	// try to parse data as a PEM encoded certificates / private keys
	var block *pem.Block
	for rest := data; len(rest) > 0; {

		// decode block
		block, rest = pem.Decode(rest)
		if block != nil {

			// decrypt PEM block, if it is encrypted
			var blockData []byte
			if x509.IsEncryptedPEMBlock(block) {
				passwordOk := false
				for _, password := range passwords {
					decrypted, err := x509.DecryptPEMBlock(block, []byte(password))
					if err != nil {
						continue
					}
					passwordOk = true
					blockData = decrypted
				}

				if !passwordOk {
					log.Errorf("An encrypted private key was found, but no specified password seems to match.")
					return nil, nil, fmt.Errorf("An encrypted private key was found, but no specified password seems to match")
				}
			} else {
				blockData = block.Bytes
			}

			// evaluate PEM block
			if block.Type == "CERTIFICATE" {

				cert, err := x509.ParseCertificate(blockData)
				if err != nil {
					log.Errorf("Data contains a PEM encoded 'CERTIFICATE' block, but parsing it failed: %s", err)
					return nil, nil, fmt.Errorf("Data contains a PEM encoded 'CERTIFICATE' block, but parsing it failed: %s", err)
				}

				certificates = append(certificates, cert)

			} else if block.Type == "RSA PRIVATE KEY" { // PKCS#1 (RSA only)

				key, err := x509.ParsePKCS1PrivateKey(blockData)
				if err != nil {
					continue
				}
				privateKeys = append(privateKeys, crypto.PrivateKey(*key))

			} else if block.Type == "PRIVATE KEY" { // PKCS#8

				key, err := pkcs8.ParsePKCS8PrivateKey(blockData)
				if err != nil {
					log.Errorf("Data contains a PEM encoded block of type 'PRIVATE KEY', but parsing the private key failed: %s", err)
					return nil, nil, fmt.Errorf("Data contains a PEM encoded block of type 'PRIVATE KEY', but parsing the private key failed: %s", err)
				}

				privateKeys = append(privateKeys, key)

			} else if block.Type == "ENCRYPTED PRIVATE KEY" { // PKCS#8

				passwordOk := false
				for _, password := range passwords {
					key, err := pkcs8.ParsePKCS8PrivateKey(blockData, []byte(password))
					if err != nil {
						continue
					}
					privateKeys = append(privateKeys, key)
					passwordOk = true
				}

				if !passwordOk {
					log.Errorf("An encrypted private key was found, but no specified password seems to match.")
					return nil, nil, fmt.Errorf("An encrypted private key was found, but no specified password seems to match")
				}

			} else {

				log.Errorf("Data contains a PEM encoded block. Expecting its type to be 'CERTIFICATE', but it's '%s'.", block.Type)
				return nil, nil, fmt.Errorf("Data contains a PEM encoded block. Expecting its type to be 'CERTIFICATE', but it's '%s'", block.Type)

			}

			// decoding succeeded
			// => file seems to be valid text
			// => trim whitespaces to ensure termination condition works properly with trailing whitespaces
			rest = []byte(strings.TrimSpace(string(rest)))
			continue
		}

		// PEM encoded block was not found...
		break
	}

	// abort, if the file is a PEM formatted file that contains at least one certificates or private key
	if len(certificates) > 0 || len(privateKeys) > 0 {
		return certificates, privateKeys, nil
	}

	// try to parse data as PKCS#7 archive (can only contain certificates)
	pkcs7, err := pkcs7.Parse(data)
	if err == nil {
		return pkcs7.Certificates, privateKeys, nil
	}

	// try to parse data as PKCS#12 archive
	// (can contain the end-entity certificate, the certificate chain and a private key)
	isPkcs12ButWrongPassword := false
	for _, password := range append(passwords, "") {
		privateKey, certificate, caCertificates, err := pkcs12.DecodeChain(data, password)
		if err != nil {
			if err == pkcs12.ErrIncorrectPassword {
				isPkcs12ButWrongPassword = true
				continue
			} else {
				log.Errorf("Reading PKCS#12 archive failed: %s", err)
				return nil, nil, fmt.Errorf("Reading PKCS#12 archive failed: %s", err)
			}
		}

		if certificate != nil {
			certificates = append(certificates, certificate)
		}

		if len(caCertificates) > 0 {
			certificates = append(certificates, caCertificates...)
		}

		if privateKey != nil {
			privateKeys = append(privateKeys, privateKey)
		}

		return certificates, privateKeys, nil
	}

	if isPkcs12ButWrongPassword {
		log.Errorf("An encrypted PKCS#12 archive was found, but no specified password seems to match.")
		return nil, nil, fmt.Errorf("An encrypted PKCS#12 archive was found, but no specified password seems to match")
	}

	log.Errorf("Data does not contain any processable certificates and/or private keys.")
	return nil, nil, fmt.Errorf("Data does not contain any processable certificates and/or private keys")
}
