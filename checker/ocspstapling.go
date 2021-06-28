// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"strconv"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"golang.org/x/crypto/ocsp"
)

// OCSPResponseInfo describes an information of OCSP response.
type OCSPResponseInfo struct {
	Response       *ocsp.Response
	ResponseStatus ocsp.ResponseStatus
}

const NoOCSPResponseStatus = -1

// CheckOCSPStapling checks OCSP Response.
func CheckOCSPStapling(issuer *x509.Certificate, ocspResponse []byte) State {
	const name = "OCSP Stapling"

	var responseInfo OCSPResponseInfo

	printDetails := func(verbose int, dnType x509util.DNType) {
		if ocspResponse == nil {
			return
		}

		if responseInfo.Response == nil && responseInfo.ResponseStatus == NoOCSPResponseStatus {
			return
		}

		printDetailsLine(4, "OCSP Response Data:")
		printDetailsLine(4, "    OCSP Response Status: %s (0x%x)", responseInfo.ResponseStatus.String(), int(responseInfo.ResponseStatus))

		if responseInfo.Response == nil && responseInfo.ResponseStatus == NoOCSPResponseStatus {
			return
		}

		printDetailsLine(4, "    Cert Status: %s", getCertStatusString(responseInfo.Response.Status))
		printDetailsLine(4, "    Produced At: %s", responseInfo.Response.ProducedAt)

		if responseInfo.Response.Status == ocsp.Revoked {
			printDetailsLine(4, "    Revocation Time: %s", responseInfo.Response.RevokedAt)
			printDetailsLine(4, "    Revocation Reason: %s (0x%x)", getCRLReasonString(responseInfo.Response.RevocationReason), responseInfo.Response.RevocationReason)
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

	var (
		status  Status
		message string
	)

	if len(ocspResponse) > 0 {
		if issuer != nil {
			response, err := ocsp.ParseResponse(ocspResponse, issuer)
			responseInfo.Response = response
			if err == nil {
				switch response.Status {
				case ocsp.Good:
					status = OK
					message = "certificate is valid"
				case ocsp.Revoked:
					status = CRITICAL
					message = "certificate has been deliberately revoked"
				case ocsp.Unknown:
					status = CRITICAL
					message = "OCSP responder doesn't know about the certificate"
				default:
					// this is ununsed
					status = UNKNOWN
					message = "OCSP unknown certificate status"
				}
				responseInfo.ResponseStatus = ocsp.Success
			} else {
				status = WARNING
				message = err.Error()

				switch e := err.(type) {
				case ocsp.ResponseError:
					responseInfo.ResponseStatus = ocsp.ResponseStatus(e.Status)
				default:
					// no response
					responseInfo.ResponseStatus = NoOCSPResponseStatus
				}
			}
		} else {
			status = CRITICAL
			message = "no issuer certificate sent"
		}
	} else {
		status = INFO
		message = "no response sent"
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

func getCertStatusString(status int) string {
	// RFC 6960 X.509 Internet Public Key Infrastructure
	//          Online Certificate Status Protocol - OCSP
	switch status {
	case ocsp.Good:
		return "good"
	case ocsp.Revoked:
		return "revoked"
	case ocsp.Unknown:
		return "unknown"
	default:
		return "unknown certificate status value: " + strconv.Itoa(status)
	}
}

func getCRLReasonString(reasonCode int) string {
	// RFC 5280 Internet X.509 Public Key Infrastructure Certificate and
	//          Certificate Revocation List (CRL) Profile
	switch reasonCode {
	case ocsp.Unspecified:
		return "unspecified"
	case ocsp.KeyCompromise:
		return "keyCompromise"
	case ocsp.CACompromise:
		return "cACompromise"
	case ocsp.AffiliationChanged:
		return "affiliationChanged"
	case ocsp.Superseded:
		return "superseded"
	case ocsp.CessationOfOperation:
		return "cessationOfOperation"
	case ocsp.CertificateHold:
		return "certificateHold"
	case ocsp.RemoveFromCRL:
		return "removeFromCRL"
	case ocsp.PrivilegeWithdrawn:
		return "privilegeWithdrawn"
	case ocsp.AACompromise:
		return "aACompromise"
	default:
		return "unknown CRL reason code: " + strconv.Itoa(reasonCode)
	}
}
