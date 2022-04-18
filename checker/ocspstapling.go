// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/ocsputil"
)

// OCSPStaplingChecker represents wheather the response from OCSP Stapling is valid.
type OCSPStaplingChecker struct {
	name    string
	status  Status
	message string
	details *OCSPResponseDetails
}

// NewOCSPStaplingChecker returns a new OCSPStaplingChecker.
func NewOCSPStaplingChecker(ocspResponse []byte, issuer *x509.Certificate, intermediateCerts []*x509.Certificate, rootCertPool *x509.CertPool, allowNonReponse bool) *OCSPStaplingChecker {
	const name = "OCSP Stapling"

	var (
		status       Status
		message      string
		responseInfo *OCSPResponseInfo
	)

	if len(ocspResponse) > 0 {
		if issuer != nil {
			responseInfo = NewOCSPResponseInfo(ocspResponse, nil, issuer, intermediateCerts, rootCertPool)
			status = responseInfo.Status
			message = responseInfo.Message
		} else {
			responseInfo = &OCSPResponseInfo{
				ResponseStatus: ocsputil.NoResponseStatus,
			}
			status = CRITICAL
			message = "ocsp: no issuer certificate sent"
		}
	} else {
		if allowNonReponse {
			status = INFO
			message = "no response sent"
		} else {
			status = WARNING
			message = "ocsp: no response sent"
		}
		responseInfo = &OCSPResponseInfo{
			ResponseStatus: ocsputil.NoResponseStatus,
		}
	}

	details := NewOCSPResponseData(responseInfo)

	return &OCSPStaplingChecker{
		name:    name,
		status:  status,
		message: message,
		details: details,
	}
}

func (c *OCSPStaplingChecker) Name() string {
	return c.name
}

func (c *OCSPStaplingChecker) Status() Status {
	return c.status
}

func (c *OCSPStaplingChecker) Message() string {
	return c.message
}

func (c *OCSPStaplingChecker) Details() interface{} {
	return c.details
}

func (c *OCSPStaplingChecker) PrintName() {
	printCheckerName(c)
}

func (c *OCSPStaplingChecker) PrintStatus() {
	printCheckerStatus(c)
}

func (c *OCSPStaplingChecker) PrintDetails() {
	printOCSPResponse(c.details)
}
