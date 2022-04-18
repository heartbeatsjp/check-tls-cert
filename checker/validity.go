// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

const timeFormat = "2006-01-02 15:04:05 -0700"

// ValidityChecker represents wheather the validity of a certificate is valid.
type ValidityChecker struct {
	name    string
	status  Status
	message string
	details *ValidityDetails
}

// NewValidityChecker returns a new ValidityChecker.
func NewValidityChecker(cert *x509.Certificate, warning int, critical int) *ValidityChecker {
	const name = "Validity"

	var (
		status  Status
		message string
		err     error
	)

	//lint:ignore SA4006 It was detected by mistake.
	if message, err = x509util.VerifyValidity(cert, critical, currentTime); err != nil {
		status = CRITICAL
		message = err.Error()
	} else if message, err = x509util.VerifyValidity(cert, warning, currentTime); err != nil {
		status = WARNING
		message = err.Error()
	} else {
		status = OK
	}

	details := NewValidityDetails(cert)

	return &ValidityChecker{
		name:    name,
		status:  status,
		message: message,
		details: details,
	}
}

func (c *ValidityChecker) Name() string {
	return c.name
}

func (c *ValidityChecker) Status() Status {
	return c.status
}

func (c *ValidityChecker) Message() string {
	return c.message
}

func (c *ValidityChecker) Details() interface{} {
	return c.details
}

func (c *ValidityChecker) PrintName() {
	printCheckerName(c)
}

func (c *ValidityChecker) PrintStatus() {
	printCheckerStatus(c)
}

func (c *ValidityChecker) PrintDetails() {
	printKeyValueIfExists(4, "Not Before", c.details.NotBefore)
	printKeyValueIfExists(4, "Not After ", c.details.NotAfter)
}

// ValidityDetails is the validity of a certificate.
type ValidityDetails struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

// NewValidityDetails returns a new ValidityDetails.
func NewValidityDetails(cert *x509.Certificate) *ValidityDetails {
	return &ValidityDetails{
		NotBefore: cert.NotBefore.Local().Format(timeFormat),
		NotAfter:  cert.NotAfter.Local().Format(timeFormat),
	}
}
