// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"encoding/asn1"

	"github.com/heartbeatsjp/check-tls-cert/ocsputil"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"golang.org/x/crypto/ocsp"
)

// CheckOCSPResponder checks the response from OCSP Responder.
func CheckOCSPResponder(targetCert *x509.Certificate, issuer *x509.Certificate, intermediateCerts []*x509.Certificate, rootCertPool *x509.CertPool) State {
	const name = "OCSP Responder"

	var responseInfo ocsputil.OCSPResponseInfo

	printDetails := func(verbose int, dnType x509util.DNType) {
		if responseInfo.Response == nil && responseInfo.ResponseStatus == ocsputil.NoResponseStatus {
			return
		}

		printDetailsLine(4, "OCSP Responder: %s", responseInfo.Server)

		printDetailsLine(4, "OCSP Response Data:")

		if responseInfo.ResponseStatus != ocsputil.NoResponseStatus {
			printDetailsLine(4, "    OCSP Response Status: %s (0x%x)", ocsputil.ResponseStatus(responseInfo.ResponseStatus).String(), int(responseInfo.ResponseStatus))
		}

		if responseInfo.Response != nil {
			printDetailsLine(4, "    Cert Status: %s", ocsputil.CertificateStatus(responseInfo.Response.Status).String())
			printDetailsLine(4, "    Produced At: %s", responseInfo.Response.ProducedAt)

			if responseInfo.Response.Status == ocsp.Revoked {
				printDetailsLine(4, "    Revocation Time: %s", responseInfo.Response.RevokedAt)
				printDetailsLine(4, "    Revocation Reason: %s (0x%x)", ocsputil.CRLReasonCode(responseInfo.Response.RevocationReason).String(), responseInfo.Response.RevocationReason)
			}
			printDetailsLine(4, "    This Update: %s", responseInfo.Response.ThisUpdate)
			if !responseInfo.Response.NextUpdate.IsZero() {
				printDetailsLine(4, "    Next Update: %s", responseInfo.Response.NextUpdate)
			}

			if responseInfo.Response.Certificate != nil {
				printDetailsLine(4, "Certificate:")
				printCertificate(responseInfo.Response.Certificate, verbose, dnType, 8)
			}
		}
	}

	var (
		status  Status
		message string
	)

	ocspServer, ocspResponse, err := ocsputil.GetOCSPResponse(targetCert, issuer)
	responseInfo.Server = ocspServer
	if ocspResponse != nil {
		if issuer != nil {
			response, err := ocsp.ParseResponseForCert(ocspResponse, targetCert, issuer)
			responseInfo.Response = response
			if err == nil {
				if response.Certificate == nil {
					if err := response.CheckSignatureFrom(issuer); err != nil {
						status = CRITICAL
						message = err.Error()
					}
				}
				if status != CRITICAL {
					if response.Status == ocsp.Good {
						status = OK
					} else {
						status = CRITICAL
					}
					message = ocsputil.CertificateStatus(response.Status).Message()
					responseInfo.ResponseStatus = ocsp.Success
				}

				if response.Certificate != nil {
					err = ocsputil.VerifyAuthorizedResponder(response.Certificate, issuer, intermediateCerts, rootCertPool)
					if err != nil {
						status = CRITICAL
						message = "ocsp: OCSP response signer's certificate error: " + err.Error()
					}
				}
			} else {
				switch e := err.(type) {
				case ocsp.ResponseError:
					if e.Status == ocsp.Unauthorized {
						status = CRITICAL
					} else {
						status = UNKNOWN
					}
					message = "ocsp: error from server: " + ocsputil.ResponseStatus(e.Status).Message()
					responseInfo.ResponseStatus = e.Status
				case ocsp.ParseError:
					status = UNKNOWN
					message = "ocsp: OCSP response parse error: " + err.Error()
					responseInfo.ResponseStatus = ocsputil.NoResponseStatus
				case asn1.StructuralError:
					status = UNKNOWN
					message = "unsupported OCSP response format"
					responseInfo.ResponseStatus = ocsputil.NoResponseStatus
				default:
					status = UNKNOWN
					message = "ocsp: " + err.Error()
					responseInfo.ResponseStatus = ocsputil.NoResponseStatus
				}
			}
		} else {
			status = CRITICAL
			message = "ocsp: no issuer certificate sent"
		}
	} else if err != nil {
		status = INFO
		message = "ocsp: " + err.Error()
	} else {
		status = INFO
		message = "ocsp: no valid OCSP responders"
	}

	state := State{
		Name:         name,
		Status:       status,
		Message:      message,
		Data:         responseInfo,
		PrintDetails: printDetails,
	}
	return state
}
