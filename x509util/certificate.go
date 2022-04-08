// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

// ParseCertificateFiles parses certifcate files in PEM format and returns certificates.
func ParseCertificateFiles(certFiles ...string) (certs []*x509.Certificate, err error) {
	var pemData []byte

	for _, certFile := range certFiles {
		if certFile != "" {
			buf, err := os.ReadFile(certFile)
			if err != nil {
				return nil, err
			}
			if !bytes.HasSuffix(buf, []byte{'\n'}) {
				buf = append(buf, '\n')
			}
			pemData = append(pemData, buf...)
		}
	}

	for len(pemData) > 0 {
		block, rest := pem.Decode(pemData)
		pemData = rest
		if block == nil {
			break
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates")
	}

	return certs, nil
}

const timeFormat = "2006-01-02 15:04:05 -0700"

// ParseCertificateFile parses a certifcate file in PEM format and returns the first certificate.
func ParseCertificateFile(certFile string) (cert *x509.Certificate, err error) {
	pemData, err := os.ReadFile(certFile)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM format")
	}
	return x509.ParseCertificate(block.Bytes)
}

// GetRootCertPool retrieves the root certificate pool.
// If root certificates are provided, return a certificate pool for them.
// If root certificates are not provided, return the system certificate pool.
func GetRootCertPool(rootCerts []*x509.Certificate, enableSSLCertDir bool) (*x509.CertPool, error) {
	var (
		roots *x509.CertPool
		err   error
	)

	if len(rootCerts) > 0 {
		roots = x509.NewCertPool()
		for _, cert := range rootCerts {
			roots.AddCert(cert)
		}
	} else {
		if !enableSSLCertDir {
			os.Setenv("SSL_CERT_DIR", ":")
		}
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, err
		}
	}

	return roots, nil
}

// GetIntermediateCertPool retrieves an intermediate certificate pool.
func GetIntermediateCertPool(intermediateCerts []*x509.Certificate) *x509.CertPool {
	intermediates := x509.NewCertPool()
	for _, cert := range intermediateCerts {
		intermediates.AddCert(cert)
	}
	return intermediates
}

// BuildCertificateChains builds certificate chains.
func BuildCertificateChains(certs []*x509.Certificate, rootCertPool *x509.CertPool) (chains [][]*x509.Certificate) {
	opts := x509.VerifyOptions{
		Roots: rootCertPool,
	}

	// If a valid root certificate is found, build a chain with it.
	for i := 0; i < len(certs); i++ {
		candidateChains, err := certs[i].Verify(opts)
		if err != nil {
			continue
		}

		for _, candidateChain := range candidateChains {
			if len(candidateChain) != 2 {
				continue
			}

			candidateRootCert := candidateChain[1]

			if !bytes.Equal(candidateRootCert.RawIssuer, candidateRootCert.RawSubject) {
				continue
			}

			var chain []*x509.Certificate
			chain = append(chain, certs[:i+1]...)
			chain = append(chain, candidateRootCert)
			chains = append(chains, chain)
		}
	}

	// If no valid root certificate is found, a chain without any root certificate is returned.
	if len(chains) == 0 {
		chains = append(chains, certs)
	}

	return chains
}

// VerifyValidity verifies the validity of the certificate.
func VerifyValidity(cert *x509.Certificate, days int) (message string, err error) {
	currentTime := time.Now()
	expirationDays := int(math.Ceil(cert.NotAfter.Sub(currentTime).Hours() / 24))

	switch {
	case cert.NotBefore.After(currentTime):
		err = fmt.Errorf("the certificate is not yet valid and will be valid on %s", cert.NotBefore.Local().Format(timeFormat))
	case cert.NotAfter.Before(currentTime):
		err = fmt.Errorf("the certificate has expired on %s", cert.NotAfter.Local().Format(timeFormat))
	case cert.NotAfter.Before(currentTime.AddDate(0, 0, days)):
		err = fmt.Errorf("the certificate will expire in %d days on %s", expirationDays, cert.NotAfter.Local().Format(timeFormat))
	default:
		message = fmt.Sprintf("the certificate will expire in %d days on %s", expirationDays, cert.NotAfter.Local().Format(timeFormat))
	}
	return
}

// VerifyCertificate verifies a certificate using the parent certificate.
func VerifyCertificate(cert *x509.Certificate, parent *x509.Certificate, forceParentToCheck bool) error {
	var messages []string

	if len(cert.Raw) == 0 {
		messages = append(messages, "certificate parse error")
	}

	if len(cert.UnhandledCriticalExtensions) > 0 {
		messages = append(messages, x509.UnhandledCriticalExtension{}.Error())
	}

	if parent == nil {
		if bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.BasicConstraintsValid && cert.IsCA {
			// Since the certificate is a self-signed root certificate, the signature check should not fail.
			if err := cert.CheckSignatureFrom(cert); err != nil {
				// Workaround for SHA-1 signatures.
				// If an error occurs due to a SHA-1 signature, ignore it.
				var ignoreError = false
				switch e := err.(type) {
				case x509.InsecureAlgorithmError:
					if x509.SignatureAlgorithm(e) == x509.SHA1WithRSA || x509.SignatureAlgorithm(e) == x509.ECDSAWithSHA1 {
						ignoreError = true
					}
				}
				if !ignoreError {
					messages = append(messages, err.Error())
				}
			}
		} else {
			if forceParentToCheck {
				// Since the certificate is not a root certificate, it must be signed by a known authority.
				messages = append(messages, x509.UnknownAuthorityError{Cert: cert}.Error())
			}
		}
	} else {
		if len(parent.Raw) == 0 {
			messages = append(messages, "parent certificate parse error")
		}

		if !bytes.Equal(cert.RawIssuer, parent.RawSubject) {
			err := x509.CertificateInvalidError{Cert: cert, Reason: x509.NameMismatch, Detail: ""}
			messages = append(messages, err.Error())
		}

		if err := cert.CheckSignatureFrom(parent); err != nil {
			messages = append(messages, err.Error()+" / parent certificate may not be correct issuer")
		}
	}

	if _, err := VerifyValidity(cert, 0); err != nil {
		messages = append(messages, err.Error())
	}

	if len(messages) > 0 {
		return errors.New(strings.Join(messages, " / "))
	}

	return nil
}
