// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
)

// CertificateChecker represents a certificate information.
type CertificateChecker struct {
	name    string
	status  Status
	message string
	details *CertificateDetails
}

func NewCertificateChecker(cert *x509.Certificate) *CertificateChecker {
	const name = "Certificate"
	message := "the certificate information is as follows"

	details := NewCertificateDetails(cert)

	return &CertificateChecker{
		name:    name,
		status:  INFO,
		message: message,
		details: details,
	}
}

func (c *CertificateChecker) Name() string {
	return c.name
}

func (c *CertificateChecker) Status() Status {
	return c.status
}

func (c *CertificateChecker) Message() string {
	return c.message
}

func (c *CertificateChecker) Details() interface{} {
	return c.details
}

func (c *CertificateChecker) PrintName() {
	printCheckerName(c)
}

func (c *CertificateChecker) PrintStatus() {
	printCheckerStatus(c)
}

func (c *CertificateChecker) PrintDetails() {
	printCertificate(4, c.details)
}
