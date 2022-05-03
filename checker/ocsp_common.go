// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"

	"github.com/heartbeatsjp/check-tls-cert/ocsputil"
	"golang.org/x/crypto/ocsp"
)

// OCSPResponseInfo describes an information of OCSP response.
type OCSPResponseInfo struct {
	Status         Status
	Message        string
	Server         string
	Response       *ocsp.Response
	ResponseStatus ocsp.ResponseStatus
}

func NewOCSPResponseInfo(ocspResponse []byte, targetCert, issuer *x509.Certificate, intermediateCerts []*x509.Certificate, rootCertPool *x509.CertPool) *OCSPResponseInfo {
	var status Status
	var message string

	responseStatus := ocsputil.NoResponseStatus
	response, err := ocsp.ParseResponseForCert(ocspResponse, targetCert, issuer)
	if err == nil {
		responseStatus = ocsp.Success

		isSigValid := true
		if response.Certificate == nil {
			if err := response.CheckSignatureFrom(issuer); err != nil {
				isSigValid = false
				status = CRITICAL
				message = err.Error()
			}
		}

		isCertInvalid := false
		if response.Certificate != nil {
			err = ocsputil.VerifyAuthorizedResponder(response.Certificate, issuer, intermediateCerts, rootCertPool, currentTime)
			if err != nil {
				isCertInvalid = true
				status = CRITICAL
				message = "ocsp: OCSP response signer's certificate error: " + err.Error()
			}
		}

		if isSigValid && !isCertInvalid {
			if response.Status == ocsp.Good {
				status = OK
			} else {
				status = CRITICAL
			}
			message = ocsputil.CertificateStatus(response.Status).Message()
		}
	} else {
		status = UNKNOWN
		switch e := err.(type) {
		case ocsp.ResponseError:
			if e.Status == ocsp.Unauthorized {
				status = CRITICAL
			} else {
				status = UNKNOWN
			}
			message = "ocsp: error from server: " + ocsputil.ResponseStatus(e.Status).Message()
			responseStatus = e.Status
		case ocsp.ParseError:
			message = "ocsp: OCSP response parse error: " + err.Error()
			responseStatus = ocsputil.NoResponseStatus
		case asn1.StructuralError:
			message = "unsupported OCSP response format"
			responseStatus = ocsputil.NoResponseStatus
		default:
			message = "ocsp: " + err.Error()
			responseStatus = ocsputil.NoResponseStatus
		}
	}

	return &OCSPResponseInfo{
		Status:         status,
		Response:       response,
		ResponseStatus: responseStatus,
		Message:        message,
	}
}

// OCSPResponseDetails is an OCSP response.
type OCSPResponseDetails struct {
	OCSPResponder    string              `json:"oCSPResponder,omitempty"`
	OCSPResponseData *OCSPResponseData   `json:"oCSPResponseData,omitempty"`
	Certificate      *CertificateDetails `json:"certificate,omitempty"`
}

type OCSPResponseData struct {
	OCSPResponseStatus string `json:"oCSPResponseStatus,omitempty"`
	CertStatus         string `json:"certStatus,omitempty"`
	ProducedAt         string `json:"producedAt,omitempty"`
	RevocationTime     string `json:"revocationTime,omitempty"`
	RevocationReason   string `json:"revocationReason,omitempty"`
	ThisUpdate         string `json:"thisUpdate,omitempty"`
	NextUpdate         string `json:"nextUpdate,omitempty"`
}

func NewOCSPResponseData(responseInfo *OCSPResponseInfo) *OCSPResponseDetails {
	var (
		oCSPResponder    string
		oCSPResponseData *OCSPResponseData
		certificate      *CertificateDetails
	)
	oCSPResponseData = &OCSPResponseData{}

	if responseInfo.Server != "" {
		oCSPResponder = responseInfo.Server
	}

	if responseInfo.Response != nil || responseInfo.ResponseStatus != ocsputil.NoResponseStatus {
		oCSPResponseData.OCSPResponseStatus = fmt.Sprintf("%s (0x%x)", ocsputil.ResponseStatus(responseInfo.ResponseStatus).String(), int(responseInfo.ResponseStatus))
	}

	if responseInfo.Response != nil {
		oCSPResponseData.CertStatus = ocsputil.CertificateStatus(responseInfo.Response.Status).String()
		oCSPResponseData.ProducedAt = responseInfo.Response.ProducedAt.Format(timeFormat)

		if responseInfo.Response.Status == ocsp.Revoked {
			oCSPResponseData.RevocationTime = responseInfo.Response.RevokedAt.Format(timeFormat)
			oCSPResponseData.RevocationReason = fmt.Sprintf("%s (0x%x)", ocsputil.CRLReasonCode(responseInfo.Response.RevocationReason).String(), responseInfo.Response.RevocationReason)
		}
		oCSPResponseData.ThisUpdate = responseInfo.Response.ThisUpdate.Format(timeFormat)
		if !responseInfo.Response.NextUpdate.IsZero() {
			oCSPResponseData.NextUpdate = responseInfo.Response.NextUpdate.Format(timeFormat)
		}

		if responseInfo.Response.Certificate != nil {
			certificate = NewCertificateDetails(responseInfo.Response.Certificate)
		}
	}
	return &OCSPResponseDetails{
		OCSPResponder:    oCSPResponder,
		OCSPResponseData: oCSPResponseData,
		Certificate:      certificate,
	}
}

func printOCSPResponse(response *OCSPResponseDetails) {
	printKeyValueIfExists(4, "OCSP Responder", response.OCSPResponder)

	if response.OCSPResponseData != nil && response.OCSPResponseData.OCSPResponseStatus != "" {
		printKey(4, "OCSP Response Data")
		printKeyValueIfExists(8, "OCSP Response Status", response.OCSPResponseData.OCSPResponseStatus)
		printKeyValueIfExists(8, "Cert Status", response.OCSPResponseData.CertStatus)
		printKeyValueIfExists(8, "Produced At", response.OCSPResponseData.ProducedAt)
		printKeyValueIfExists(8, "Revocation Time", response.OCSPResponseData.RevocationTime)
		printKeyValueIfExists(8, "Revocation Reason", response.OCSPResponseData.RevocationReason)
		printKeyValueIfExists(8, "This Update", response.OCSPResponseData.ThisUpdate)
		printKeyValueIfExists(8, "Next Update", response.OCSPResponseData.NextUpdate)

		if response.Certificate != nil {
			printKey(4, "Certificate")
			printCertificate(8, response.Certificate)
		}
	}
}
