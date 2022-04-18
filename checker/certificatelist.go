// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"strings"
)

// CertificateListChecker represents wheather peer certificates are valid.
type CertificateListChecker struct {
	name    string
	status  Status
	message string
	details CertificateListDetails
}

func NewCertificateListChecker(certs []*x509.Certificate) *CertificateListChecker {
	const name = "Peer Certificate List"

	n := len(certs)
	certInfoList := make([]CertificateInfo, n)

	var parent *x509.Certificate
	for i := 0; i < n; i++ {
		cert := certs[n-i-1]
		certInfo := NewCertificateInfo(cert, parent, false)
		certInfoList[n-i-1] = certInfo
		parent = cert
	}

	status := OK
	message := "certificates are valid"
	var messages []string

	for _, certInfo := range certInfoList {
		if certInfo.Status == ERROR {
			status = CRITICAL
			messages = append(messages, certInfo.Error)
		}
	}

	if len(messages) > 0 {
		message = strings.Join(messages, " / ")
	}

	if len(certInfoList) == 0 {
		status = CRITICAL
		message = "no certificate"
	}

	details := NewCertificateListDetails(certInfoList)

	return &CertificateListChecker{
		name:    name,
		status:  status,
		message: message,
		details: details,
	}
}

func (c *CertificateListChecker) Name() string {
	return c.name
}

func (c *CertificateListChecker) Status() Status {
	return c.status
}

func (c *CertificateListChecker) Message() string {
	return c.message
}

func (c *CertificateListChecker) Details() interface{} {
	return c.details
}

func (c *CertificateListChecker) PrintName() {
	printCheckerName(c)
}

func (c *CertificateListChecker) PrintStatus() {
	printCheckerStatus(c)
}

func (c *CertificateListChecker) PrintDetails() {
	for _, certInfo := range c.details {
		printIndentedLine(4, "- %s: %s", certInfo.Status.ColorString(), certInfo.CommonName)
		printKeyValueIfExists(8, "Subject   ", certInfo.Subject)
		printKeyValueIfExists(8, "Issuer    ", certInfo.Issuer)
		printKeyValueIfExists(8, "Expiration", certInfo.Expiration)
		printKeyValueIfExists(8, "Message   ", certInfo.Message)
		printKeyValueIfExists(8, "Error     ", certInfo.Error)
	}
}

type CertificateListDetails []CertificateInfo

func NewCertificateListDetails(list []CertificateInfo) CertificateListDetails {
	return list
}
