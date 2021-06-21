// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package x509util

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"time"
)

// ParseCertificateFiles parses certifcate files in PEM format and returns certificates.
func ParseCertificateFiles(certFiles ...string) (certs []*x509.Certificate, err error) {
	var pemData []byte

	for _, certFile := range certFiles {
		if certFile != "" {
			f, err := os.Open(certFile)
			if err != nil {
				return nil, err
			}
			buf, err := io.ReadAll(f)
			if err != nil {
				return nil, err
			}
			pemData = append(pemData, buf...)
		}
	}

	for len(pemData) > 0 {
		block, rest := pem.Decode(pemData)
		pemData = rest

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
	var (
		f       *os.File
		pemData []byte
	)

	if f, err = os.Open(certFile); err != nil {
		return nil, err
	}

	if pemData, err = io.ReadAll(f); err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, errors.New("no PEM format")
	}
	return x509.ParseCertificate(block.Bytes)
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
