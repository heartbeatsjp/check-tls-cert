// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/ocsputil"
)

// OCSPResponderChecker represents wheather the response from OCSP Responder is valie.
type OCSPResponderChecker struct {
	name    string
	status  Status
	message string
	details *OCSPResponseDetails
}

func NewOCSPResponderChecker(targetCert *x509.Certificate, issuer *x509.Certificate, intermediateCerts []*x509.Certificate, rootCertPool *x509.CertPool) *OCSPResponderChecker {
	const name = "OCSP Responder"

	var responseInfo *OCSPResponseInfo

	var (
		status  Status
		message string
	)

	ocspServer, ocspResponse, err := ocsputil.GetOCSPResponse(targetCert, issuer)
	if ocspResponse != nil {
		if issuer != nil {
			responseInfo = NewOCSPResponseInfo(ocspResponse, targetCert, issuer, intermediateCerts, rootCertPool)
			status = responseInfo.Status
			message = responseInfo.Message
		} else {
			status = CRITICAL
			message = "ocsp: no issuer certificate sent"
			responseInfo.ResponseStatus = ocsputil.NoResponseStatus
		}
	} else if err != nil {
		status = INFO
		message = "ocsp: " + err.Error()
		responseInfo.ResponseStatus = ocsputil.NoResponseStatus
	} else {
		status = INFO
		message = "ocsp: no valid OCSP responders"
		responseInfo.ResponseStatus = ocsputil.NoResponseStatus
	}

	responseInfo.Server = ocspServer

	details := NewOCSPResponseData(responseInfo)

	return &OCSPResponderChecker{
		name:    name,
		status:  status,
		message: message,
		details: details,
	}
}

func (c *OCSPResponderChecker) Name() string {
	return c.name
}

func (c *OCSPResponderChecker) Status() Status {
	return c.status
}

func (c *OCSPResponderChecker) Message() string {
	return c.message
}

func (c *OCSPResponderChecker) Details() interface{} {
	return c.details
}

func (c *OCSPResponderChecker) PrintName() {
	printCheckerName(c)
}

func (c *OCSPResponderChecker) PrintStatus() {
	printCheckerStatus(c)
}

func (c *OCSPResponderChecker) PrintDetails() {
	printOCSPResponse(c.details)
}
