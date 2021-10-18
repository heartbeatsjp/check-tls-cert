// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ocsputil

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"golang.org/x/crypto/ocsp"
)

const ocspClientTimeout = 5

const NoResponseStatus = -1

// OCSPResponseInfo describes an information of OCSP response.
type OCSPResponseInfo struct {
	Server         string
	Response       *ocsp.Response
	ResponseStatus ocsp.ResponseStatus
}

// CertificateStatus is an OCSP certificate status.
type CertificateStatus int

const (
	// Good means that the certificate is valid.
	Good CertificateStatus = iota
	// Revoked means that the certificate has been deliberately revoked.
	Revoked
	// Unknown means that the OCSP responder doesn't know about the certificate.
	Unknown
)

var certificateStatusString = [...]string{
	Good:    "good",
	Revoked: "revoked",
	Unknown: "unknown",
}

func (c CertificateStatus) String() string {
	i := int(c)
	if 0 <= i && i < len(certificateStatusString) {
		return certificateStatusString[i]
	}
	return "unknown OCSP certificate status: " + strconv.Itoa(i)
}

var certificateStatusMessage = [...]string{
	Good:    "certificate is valid",
	Revoked: "certificate has been deliberately revoked",
	Unknown: "OCSP responder doesn't know about the certificate",
}

func (c CertificateStatus) Message() string {
	i := int(c)
	if 0 <= i && i < len(certificateStatusMessage) {
		return certificateStatusMessage[i]
	}
	return "unknown OCSP certificate status: " + strconv.Itoa(i)
}

// CRLReasonCode is a CRL reason code.
type CRLReasonCode int

const (
	Unspecified          CRLReasonCode = 0
	KeyCompromise        CRLReasonCode = 1
	CACompromise         CRLReasonCode = 2
	AffiliationChanged   CRLReasonCode = 3
	Superseded           CRLReasonCode = 4
	CessationOfOperation CRLReasonCode = 5
	CertificateHold      CRLReasonCode = 6
	RemoveFromCRL        CRLReasonCode = 8
	PrivilegeWithdrawn   CRLReasonCode = 9
	AACompromise         CRLReasonCode = 10
)

func (c CRLReasonCode) String() string {
	switch c {
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
		return "unknown CRL reason code: " + strconv.Itoa(int(c))
	}
}

// ResponseStatus is a wrapper of ocsp.ResponseStatus.
type ResponseStatus ocsp.ResponseStatus

const (
	Successful       ResponseStatus = 0
	MalformedRequest ResponseStatus = 1
	InternalError    ResponseStatus = 2
	TryLater         ResponseStatus = 3
	SigRequired      ResponseStatus = 5
	Unauthorized     ResponseStatus = 6
)

func (r ResponseStatus) String() string {
	switch r {
	case Successful:
		return "successful"
	case MalformedRequest:
		return "malformedRequest"
	case InternalError:
		return "internalError"
	case TryLater:
		return "tryLater"
	case SigRequired:
		return "sigRequired"
	case Unauthorized:
		return "unauthorized"
	default:
		return "unknown OCSP response status: " + strconv.Itoa(int(r))
	}
}

func (r ResponseStatus) Message() string {
	switch r {
	case Successful:
		return "response has valid confirmations"
	case MalformedRequest:
		return "illegal confirmation request"
	case InternalError:
		return "internal error in issuer"
	case TryLater:
		return "try again later"
	case SigRequired:
		return "must sign the request"
	case Unauthorized:
		return "request unauthorized"
	default:
		return "unknown OCSP response status: " + strconv.Itoa(int(r))
	}
}

// GetOCSPResponse sends the request to the OCSP Responder and gets the response from the OCSP Responder.
func GetOCSPResponse(cert *x509.Certificate, issuer *x509.Certificate) (string, []byte, error) {
	var err error

	if cert == nil {
		return "", nil, errors.New("no server certificate")
	}

	if issuer == nil {
		return "", nil, errors.New("no issuer certificate")
	}

	if len(cert.OCSPServer) == 0 {
		return "", nil, errors.New("no OCSP server in certificate")
	}

	requestOption := ocsp.RequestOptions{
		Hash: crypto.SHA1,
	}

	ocspRequest, err := ocsp.CreateRequest(cert, issuer, &requestOption)
	if err != nil {
		return "", nil, err
	}
	encodedOCSPRequest := base64.StdEncoding.EncodeToString(ocspRequest)

	client := &http.Client{
		Timeout: ocspClientTimeout * time.Second,
	}

	var ocspResponse []byte
	var server string

	for _, server = range cert.OCSPServer {
		var req *http.Request

		if len(encodedOCSPRequest) < 255 {
			if !strings.HasSuffix(server, "/") {
				server = server + "/"
			}
			u, _ := url.Parse(server + encodedOCSPRequest)
			req, err = http.NewRequest("GET", u.String(), nil)
			if err != nil {
				continue
			}
		} else {
			req, err = http.NewRequest("POST", server, strings.NewReader(string(ocspRequest)))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/ocsp-request")
		}

		var resp *http.Response
		resp, err = client.Do(req)
		if err != nil {
			continue
		}

		ocspResponse, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err == nil {
			break
		}
	}

	return server, ocspResponse, err
}

// VerifyAuthorizedResponder verifies the certificate of the authorized responder.
func VerifyAuthorizedResponder(responderCert, issuer *x509.Certificate, intermediateCerts, rootCerts []*x509.Certificate) error {
	if responderCert == nil {
		return nil
	}

	// See RFC 6969 4.2.2.2. Authorized Responders
	if responderCert.Equal(issuer) {
		// valid
	} else if issuer.Subject.String() == responderCert.Issuer.String() {
		incompatibleKeyUsage := true
		for _, usage := range responderCert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageOCSPSigning {
				incompatibleKeyUsage = false
			}
		}
		if incompatibleKeyUsage {
			return errors.New("certificate specifies an incompatible key usage")
		}
		if err := responderCert.CheckSignatureFrom(issuer); err != nil {
			return errors.New("signer's certificate does not issued by target certificate's issuer")
		}
	} else {
		return errors.New("invalid certificate")
	}

	roots, err := x509util.GetRootCertPool(rootCerts)
	if err != nil {
		return err
	}
	intermediates := x509util.GetIntermediateCertPool(intermediateCerts)

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	_, err = responderCert.Verify(opts)
	return err
}
