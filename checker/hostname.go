// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"fmt"
)

// HostnameChecker represents whether a hostname is valid for a certificate.
type HostnameChecker struct {
	name    string
	status  Status
	message string
	details *HostnameDetails
}

func NewHostnameChecker(hostname string, cert *x509.Certificate) *HostnameChecker {
	const name = "Hostname"

	var (
		status  Status
		message string
	)

	err := cert.VerifyHostname(hostname)
	if err != nil {
		status = CRITICAL
		message = fmt.Sprintf("the hostname '%s' is invalid for the certificate / %s", hostname, err.Error())
	} else {
		status = OK
		message = fmt.Sprintf("the hostname '%s' is valid for the certificate", hostname)
	}

	details := NewHostnameDetails(cert)

	return &HostnameChecker{
		name:    name,
		status:  status,
		message: message,
		details: details,
	}
}

func (c *HostnameChecker) Name() string {
	return c.name
}

func (c *HostnameChecker) Status() Status {
	return c.status
}

func (c *HostnameChecker) Message() string {
	return c.message
}

func (c *HostnameChecker) Details() interface{} {
	return c.details
}

func (c *HostnameChecker) PrintName() {
	printCheckerName(c)
}

func (c *HostnameChecker) PrintStatus() {
	printCheckerStatus(c)
}

func (c *HostnameChecker) PrintDetails() {
	printKeyValueIfExists(4, "Common Name", c.details.CommonName)
	if len(c.details.SubjectAltName) > 0 {
		printSubjectAltName(4, c.details.SubjectAltName)
	}
}

type HostnameDetails struct {
	CommonName     string           `json:"commonName"`
	SubjectAltName []subjectAltName `json:"subjectAltName,omitempty"`
}

func NewHostnameDetails(cert *x509.Certificate) *HostnameDetails {
	return &HostnameDetails{
		CommonName:     cert.Subject.CommonName,
		SubjectAltName: getSubjectAltNames(cert),
	}
}
