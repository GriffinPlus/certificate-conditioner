package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/integrii/flaggy"
	log "github.com/sirupsen/logrus"
)

type ConditionCommand struct {
	inFilePaths                 []string           // condition --in <path>
	inPasswords                 []string           // condition --in-pass <password>
	outCertificatePath          string             // condition --out-cert <path>
	outCertificateEncoding      string             // condition --out-cert-encoding <encoding>
	outCertificateChainPath     string             // condition --out-chain <path>
	outCertificateChainEncoding string             // condition --out-chain-encoding <encoding>
	outPrivateKeyPath           string             // condition --out-key <path>
	outPrivateKeyFormat         string             // condition --out-key-format <format>
	outPrivateKeyEncoding       string             // condition --out-key-encoding <encoding>
	outPrivateKeyPassword       string             // condition --out-key-pass <password>
	subcommand                  *flaggy.Subcommand // flaggy's subcommand representing the 'condition' subcommand
}

// NewConditionCommand creates a new command handling the 'condition' subcommand.
func NewConditionCommand() *ConditionCommand {
	return &ConditionCommand{}
}

// AddFlaggySubcommand adds the 'condition' subcommand to flaggy.
func (cmd *ConditionCommand) AddFlaggySubcommand() *flaggy.Subcommand {

	cmd.subcommand = flaggy.NewSubcommand("condition")
	cmd.subcommand.Description = "Condition an end-entity certificate (optionally with private key) for use with an application"
	cmd.subcommand.StringSlice(&cmd.inFilePaths, "", "in", "File containing a certificate or private key to process (may be specified multiple times)")
	cmd.subcommand.StringSlice(&cmd.inPasswords, "", "in-password", "Password that is needed to decrypt the private key file (optional, may be specified multiple times)")
	cmd.subcommand.String(&cmd.outCertificatePath, "", "out-certificate", "File receiving the end-entity certificate")
	cmd.subcommand.String(&cmd.outCertificateEncoding, "", "out-certificate-encoding", "Encoding of the file receiving the end-entity certificate (can be 'der' or 'pem' (default))")
	cmd.subcommand.String(&cmd.outCertificateChainPath, "", "out-chain", "File receiving the certificate chain")
	cmd.subcommand.String(&cmd.outCertificateChainEncoding, "", "out-chain-encoding", "Encoding of the file receiving the certificate chain (can be 'der' or 'pem' (default))")
	cmd.subcommand.String(&cmd.outPrivateKeyPath, "", "out-key", "File receiving the private key belonging to the end-entity certificate")
	cmd.subcommand.String(&cmd.outPrivateKeyFormat, "", "out-key-format", "Format of the file receiving the private key belonging to the end-entity certificate (can be 'pkcs1' or 'pkcs8' (default))")
	cmd.subcommand.String(&cmd.outPrivateKeyEncoding, "", "out-key-encoding", "Encoding of the file receiving the private key (can be 'der' or 'pem' (default))")
	cmd.subcommand.String(&cmd.outPrivateKeyPassword, "", "out-key-password", "Password to apply to the private key file")

	flaggy.AttachSubcommand(cmd.subcommand, 1)

	return cmd.subcommand
}

// IsSubcommandUsed checks whether the 'condition' subcommand was used in the command line.
func (cmd *ConditionCommand) IsSubcommandUsed() bool {
	return cmd.subcommand.Used
}

// ValidateArguments checks whether the specified arguments for the 'condition' subcommand are valid.
func (cmd *ConditionCommand) ValidateArguments() error {

	// ensure that at least one file is specified
	if len(cmd.inFilePaths) == 0 {
		return fmt.Errorf("No file to process specified")
	}

	// validate the certificate encoding, if specified
	cmd.outCertificateEncoding = strings.ToLower(cmd.outCertificateEncoding)
	switch cmd.outCertificateEncoding {
	case "":
		cmd.outCertificateEncoding = "pem"
	case "der":
	case "pem":
	default:
		return fmt.Errorf("The certificate encoding must be 'der' or 'pem'")
	}

	// validate the certificate chain format, if specified
	cmd.outCertificateChainEncoding = strings.ToLower(cmd.outCertificateChainEncoding)
	switch cmd.outCertificateChainEncoding {
	case "":
		cmd.outCertificateChainEncoding = "pem"
	case "der":
	case "pem":
	default:
		return fmt.Errorf("The certificate chain encoding must be 'der' or 'pem'")
	}

	// validate the private key format, if specified
	cmd.outPrivateKeyFormat = strings.ToLower(cmd.outPrivateKeyFormat)
	switch cmd.outPrivateKeyFormat {
	case "":
		cmd.outPrivateKeyFormat = "pkcs8"
	case "pkcs1":
	case "pkcs8":
	default:
		return fmt.Errorf("The private key format must be 'pkcs1' or 'pkcs8'")
	}

	// validate the private key encoding, if specified
	cmd.outPrivateKeyEncoding = strings.ToLower(cmd.outPrivateKeyEncoding)
	switch cmd.outPrivateKeyEncoding {
	case "":
		cmd.outPrivateKeyEncoding = "pem"
	case "der":
	case "pem":
	default:
		return fmt.Errorf("The private key encoding must be 'der' or 'pem'")
	}

	return nil
}

// Execute performs the actual work of the 'condition' subcommand.
func (cmd *ConditionCommand) Execute() error {

	// load all specified certificates and private keys
	certificates, keys, err := loadCertificatesAndPrivateKeys(cmd.inFilePaths, cmd.inPasswords)
	if err != nil {
		return err
	}

	// categorize certificates: end-entity certificates, CA certificates
	endEntityCertificates, caCertificates := splitCertificatesByCategory(certificates)

	// abort, if no end-entity certificate was found
	if len(endEntityCertificates) == 0 {
		log.Errorf("No end-entity certificate was specified.")
		return fmt.Errorf("No end-entity certificate was specified")
	}

	// abort, if more than one end-entity certificate was found
	if len(endEntityCertificates) > 1 {
		log.Errorf("Multiple end-entity certificates were specified, cannot determine which to use.")
		return fmt.Errorf("Multiple end-entity certificates were specified, cannot determine which to use")
	}

	// found the end-entity certificate
	certificate := endEntityCertificates[0]

	// check whether there is a matching private key for it
	var key crypto.PrivateKey = nil
	for _, k := range keys {
		match, err := isPrivateKeyToPublicKey(k, certificate.PublicKey)
		if err != nil {
			return fmt.Errorf("Determing whether private key and public key belongs together failed: %s", err)
		}
		if match {
			key = k
			break
		}
	}

	// abort, if at least one private key was specified, but no one belongs to the selected certificate
	// (covers writing PKCS#7 and PKCS#12 with optional private keys)
	if len(keys) > 0 && key == nil {
		log.Errorf("None of the specified private key(s) seems to belong to the selected certificate.")
		return fmt.Errorf("None of the specified private key(s) seems to belong to the selected certificate")
	}

	// walk along the certificate chain up the root to collect all CA certificates, download them, if necessary and possible
	currentCertificate := certificate
	chain := []*x509.Certificate{}
	log.Infof("Starting with specified end-entity certificate (%s), looking for issuer certificates...", currentCertificate.Subject.String())
outer:
	for {
		// print the selected certificate
		printCertificate(currentCertificate, "Selected certificate:")

		// abort, if the current certificate is a self-signed certificate (root certificate)
		if currentCertificate.Subject.String() == currentCertificate.Issuer.String() {
			break
		}

		// check whether the certificate of the issuer was specified
		for _, cacert := range caCertificates {
			valid, _ := isIssuerCertificate(currentCertificate, cacert)
			if valid {
				log.Infof("Issuer certificate (%s) was specified, taking it...", currentCertificate.Issuer.String())
				chain = append(chain, cacert)
				currentCertificate = cacert
				continue outer
			}
		}

		// try to download the issuer certificate, if it was not specified explicitly
		log.Infof("Issuer certificate (%s) was not specified, trying to download it...", currentCertificate.Issuer.String())
		for _, url := range currentCertificate.IssuingCertificateURL {

			// download certificate
			log.Infof("Downloading issuer certificate from %s...", url)
			response, err := http.Get(url)
			if err != nil {
				log.Errorf("Downloading issuer certificate from %s failed: %s", url, err)
				continue
			}
			defer response.Body.Close()

			// read certificate data from response body
			data, err := ioutil.ReadAll(response.Body)
			if err != nil {
				log.Errorf("Reading issuer certificate from failed: %s", err)
				continue
			}

			// try to parse the downloaded file as a collection of certificates
			// (in most cases it's only one certificate)
			certs, _, err := parseCertificatesOrPrivateKeys(data, []string{})
			if err != nil {
				log.Errorf("Parsing the downloaded certificate (%s) failed: %s", url, err)
				continue
			}

			// log parsed certificate(s)
			// and check whether the certificate is a the issuer certificate of the specified certificate
			for i, cert := range certs {
				printCertificate(cert, fmt.Sprintf("Parsing certificate (%d/%d) in downloaded file (%s) succeeded...", i+1, len(certs), url))
				isIssuer, err := isIssuerCertificate(currentCertificate, cert)
				if err == nil && isIssuer {
					log.Infof("Found matching issuer certificate (%s).", cert.Subject.String())
					chain = append(chain, cert)
					currentCertificate = cert
					continue outer
				}
			}
		}

		// the issuer certificate could not be obtained
		log.Errorf("The issuer certificate of the certificate (subject: %s) could not be obtained.", currentCertificate.Subject.String())
		return fmt.Errorf("The issuer certificate of the certificate (subject: %s) could not be obtained", currentCertificate.Subject.String())
	}

	certificate = endEntityCertificates[0]

	if len(cmd.outCertificatePath) > 0 {

		// open file for writing (all users are allowed to access it)
		file, err := os.OpenFile(cmd.outCertificatePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Errorf("Failed to open file (%s) for writing: %s", cmd.outCertificatePath, err)
			return err
		}
		defer file.Close()

		// write appropriately encoded certificate
		switch strings.ToLower(cmd.outCertificateEncoding) {
		case "der":
			if _, err := file.Write(certificate.Raw); err != nil {
				log.Errorf("Failed to write certificate to file (%s): %s", cmd.outCertificatePath, err)
				return err
			}
		case "pem":
			log.Infof("Writing certificate (%s) to file (%s)...", certificate.Subject.String(), cmd.outCertificatePath)
			if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
				log.Errorf("Failed to write certificate to file (%s): %s", cmd.outCertificatePath, err)
				return err
			}
		default:
			log.Panicf("Unhandled certificate format (%s)", cmd.outCertificateEncoding)
		}
	}

	if len(cmd.outCertificateChainPath) > 0 {

		// open file for writing (all users are allowed to access it)
		file, err := os.OpenFile(cmd.outCertificateChainPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
		if err != nil {
			log.Errorf("Failed to open file (%s) for writing: %s", cmd.outCertificateChainPath, err)
			return err
		}
		defer file.Close()

		// write certificate chain
		for _, certificate := range chain {
			switch strings.ToLower(cmd.outCertificateChainEncoding) {
			case "der":
				if _, err := file.Write(certificate.Raw); err != nil {
					log.Errorf("Failed to write certificate chain to file (%s): %s", cmd.outCertificateChainPath, err)
					return err
				}
			case "pem":
				log.Infof("Writing certificate (%s) to file (%s)...", certificate.Subject.String(), cmd.outCertificateChainPath)
				if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
					log.Errorf("Failed to write certificate chain to file (%s): %s", cmd.outCertificateChainPath, err)
					return err
				}
			default:
				log.Panicf("Unhandled certificate chain format (%s)", cmd.outCertificateChainEncoding)
			}
		}
	}

	if len(cmd.outPrivateKeyPath) > 0 {

		// abort, if no key is available
		if key == nil {
			log.Errorf("Cannot write private key as no private key was specified.")
			return fmt.Errorf("Cannot write private key as no private key was specified")
		}

		// prepare writing the private key using the specified format
		buffer := bytes.NewBufferString("")
		log.Infof("Writing private key to file (%s)...", cmd.outPrivateKeyPath)
		switch strings.ToLower(cmd.outPrivateKeyFormat) {
		case "pkcs1":
			err = writePkcs1PrivateKey(buffer, key, cmd.outPrivateKeyPassword)
		case "pkcs8":
			err = writePkcs8PrivateKey(buffer, key, cmd.outPrivateKeyPassword)
		default:
			log.Panicf("Unhandled private key format (%s)", cmd.outPrivateKeyFormat)
		}

		// open file for writing (only current user is allowed to access it)
		file, err := os.OpenFile(cmd.outPrivateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			log.Errorf("Failed to open file (%s) for writing: %s", cmd.outPrivateKeyPath, err)
			return err
		}
		defer file.Close()

		// encode the formatted kry as specified and write it to the specified file
		switch strings.ToLower(cmd.outPrivateKeyEncoding) {
		case "der":
			if _, err := file.Write(buffer.Bytes()); err != nil {
				log.Errorf("Failed to write private key to file (%s): %s", cmd.outPrivateKeyPath, err)
				return err
			}
		case "pem":
			log.Infof("Writing private key to file (%s)...", cmd.outPrivateKeyPath)
			if err := pem.Encode(file, &pem.Block{Type: "CERTIFICATE", Bytes: buffer.Bytes()}); err != nil {
				log.Errorf("Failed to write private key to file (%s): %s", cmd.outPrivateKeyPath, err)
				return err
			}
		default:
			log.Panicf("Unhandled private key encoding (%s)", cmd.outPrivateKeyEncoding)
		}
	}

	return nil
}
