// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CertificateInfo describes a status of a certificate.
type CertificateInfo struct {
	CommonName  string
	Certificate *x509.Certificate
	Status      Status
	Message     string
}

func getCertificateInfo(cert *x509.Certificate, parent *x509.Certificate, forceParentToCheck bool) CertificateInfo {
	status := OK
	var messages []string

	if parent == nil {
		if cert.Issuer.String() == cert.Subject.String() {
			// Since the certificate is a self-signed root certificate, the signature check should not fail.
			if err := cert.CheckSignatureFrom(cert); err != nil {
				status = ERROR
				messages = append(messages, err.Error())
			}
		} else {
			if forceParentToCheck {
				// Since the certificate is not a root certificate, it must be signed by a known authority.
				status = ERROR
				messages = append(messages, x509.UnknownAuthorityError{Cert: cert}.Error())
			}
		}
	} else {
		if err := cert.CheckSignatureFrom(parent); err != nil {
			status = ERROR
			messages = append(messages, err.Error()+" / parent certificate may not be correct issuer")
		}
	}

	if _, err := x509util.VerifyValidity(cert, 0); err != nil {
		status = ERROR
		messages = append(messages, err.Error())
	}

	var message string
	if len(messages) > 0 {
		message = strings.Join(messages, " / ")
	}

	certInfo := CertificateInfo{
		CommonName:  cert.Subject.CommonName,
		Certificate: cert,
		Status:      status,
		Message:     message,
	}
	return certInfo
}
