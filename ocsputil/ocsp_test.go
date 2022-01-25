// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ocsputil_test

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/ocsputil"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

func TestCertificateStatusString(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("good", ocsputil.Good.String())
	assert.Equal("revoked", ocsputil.Revoked.String())
	assert.Equal("unknown", ocsputil.Unknown.String())

	assert.Equal("unknown OCSP certificate status: -1", ocsputil.CertificateStatus(-1).String())
	assert.Equal("unknown OCSP certificate status: 3", ocsputil.CertificateStatus(3).String())
}

func TestCertificateStatusMessage(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("certificate is valid", ocsputil.Good.Message())
	assert.Equal("certificate has been deliberately revoked", ocsputil.Revoked.Message())
	assert.Equal("OCSP responder doesn't know about the certificate", ocsputil.Unknown.Message())

	assert.Equal("unknown OCSP certificate status: -1", ocsputil.CertificateStatus(-1).Message())
	assert.Equal("unknown OCSP certificate status: 3", ocsputil.CertificateStatus(3).Message())
}

func TestCRLReasonCodeString(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("unspecified", ocsputil.Unspecified.String())
	assert.Equal("keyCompromise", ocsputil.KeyCompromise.String())
	assert.Equal("cACompromise", ocsputil.CACompromise.String())
	assert.Equal("affiliationChanged", ocsputil.AffiliationChanged.String())
	assert.Equal("superseded", ocsputil.Superseded.String())
	assert.Equal("cessationOfOperation", ocsputil.CessationOfOperation.String())
	assert.Equal("certificateHold", ocsputil.CertificateHold.String())
	assert.Equal("removeFromCRL", ocsputil.RemoveFromCRL.String())
	assert.Equal("privilegeWithdrawn", ocsputil.PrivilegeWithdrawn.String())
	assert.Equal("aACompromise", ocsputil.AACompromise.String())

	assert.Equal("unknown CRL reason code: -1", ocsputil.CRLReasonCode(-1).String())
	assert.Equal("unknown CRL reason code: 11", ocsputil.CRLReasonCode(11).String())
}

func TestResponseStatusString(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("successful", ocsputil.Successful.String())
	assert.Equal("malformedRequest", ocsputil.MalformedRequest.String())
	assert.Equal("internalError", ocsputil.InternalError.String())
	assert.Equal("tryLater", ocsputil.TryLater.String())
	assert.Equal("sigRequired", ocsputil.SigRequired.String())
	assert.Equal("unauthorized", ocsputil.Unauthorized.String())

	assert.Equal("unknown OCSP response status: -1", ocsputil.ResponseStatus(-1).String())
	assert.Equal("unknown OCSP response status: 7", ocsputil.ResponseStatus(7).String())
}

func TestResponseStatusMessage(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("response has valid confirmations", ocsputil.Successful.Message())
	assert.Equal("illegal confirmation request", ocsputil.MalformedRequest.Message())
	assert.Equal("internal error in issuer", ocsputil.InternalError.Message())
	assert.Equal("try again later", ocsputil.TryLater.Message())
	assert.Equal("must sign the request", ocsputil.SigRequired.Message())
	assert.Equal("request unauthorized", ocsputil.Unauthorized.Message())

	assert.Equal("unknown OCSP response status: -1", ocsputil.ResponseStatus(-1).Message())
	assert.Equal("unknown OCSP response status: 7", ocsputil.ResponseStatus(7).Message())
}

func TestGetOCSPResponse(t *testing.T) {
	var (
		server        string
		responseBytes []byte
		err           error
	)
	assert := assert.New(t)

	// no OCSP responder

	issuer, _ := x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	targetCert, _ := x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")

	_, _, err = ocsputil.GetOCSPResponse(nil, nil)
	assert.NotNil(err)
	assert.EqualError(err, "no server certificate")

	_, _, err = ocsputil.GetOCSPResponse(targetCert, nil)
	assert.NotNil(err)
	assert.EqualError(err, "no issuer certificate")

	_, _, err = ocsputil.GetOCSPResponse(targetCert, issuer)
	assert.NotNil(err)
	assert.EqualError(err, "no OCSP server in certificate")

	// real OCSP responder

	hostname := "www.google.com"
	tlsConfig := tls.Config{
		ServerName:             hostname,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
	}

	dialer := net.Dialer{Timeout: time.Second * time.Duration(5)}
	conn, _ := tls.DialWithDialer(&dialer, "tcp4", hostname+":443", &tlsConfig)
	defer conn.Close()
	connectionState := conn.ConnectionState()
	certs := connectionState.PeerCertificates
	targetCert = certs[0]
	issuer = certs[1]

	server, responseBytes, err = ocsputil.GetOCSPResponse(targetCert, issuer)
	assert.Nil(err)
	assert.NotEmpty(server)
	response, _ := ocsp.ParseResponseForCert(responseBytes, targetCert, issuer)
	assert.Equal(ocsputil.Good, ocsputil.CertificateStatus(response.Status))
}

func TestVerifyAuthorizedResponder(t *testing.T) {
	var (
		template      ocsp.Response
		responseBytes []byte
		response      *ocsp.Response
		err           error
	)
	assert := assert.New(t)

	privateKeyInfo, _ := x509util.ParsePrivateKeyFile("../test/testdata/pki/private/ca-intermediate-a-rsa-ocsp-responder.key", nil)
	responderCert, _ := x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa-ocsp-responder.crt")
	issuerCert, _ := x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	targetCert, _ := x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	intermediateCerts := []*x509.Certificate{issuerCert}
	rootCerts, _ := x509util.ParseCertificateFiles("../test/testdata/pki/root-ca/ca-root.pem")
	rootCertPool, _ := x509util.GetRootCertPool(rootCerts, false)

	priv := privateKeyInfo.Key.(*rsa.PrivateKey)

	// no response, no issuer
	err = ocsputil.VerifyAuthorizedResponder(nil, nil, intermediateCerts, rootCertPool)
	assert.Nil(err)

	// no response
	err = ocsputil.VerifyAuthorizedResponder(nil, issuerCert, intermediateCerts, rootCertPool)
	assert.Nil(err)

	// Response status: good
	// OK: certificate is valid
	//     OCSP Response Data:
	//         OCSP Response Status: success (0x0)
	//         Cert Status: good
	//         Produced At: 2021-06-28 06:39:00 +0000 UTC
	//         This Update: 2021-06-27 06:39:22 +0000 UTC
	//         Next Update: 2021-06-29 06:39:22 +0000 UTC
	//     Certificate:
	//         Issuer : CN=Intermediate CA A RSA
	//         Subject: CN=Intermediate CA A RSA OCSP Responder
	//         Validity:
	//             Not Before: 2021-06-28 06:23:10 +0000 UTC
	//             Not After : 2022-06-28 06:23:10 +0000 UTC
	//         Subject Public Key Info:
	//             Public Key Algorithm: RSA
	//                 RSA Public-Key: (2048 bit)
	//                 Modulus:
	//                     00:fe:6b:e6:fc:5a:21:e3:34:74:24:cc:73:fb:d4:
	//                     ...(omitted)
	//                 Exponent: 65537 (0x10001)
	template = ocsp.Response{
		SerialNumber: targetCert.SerialNumber,
		Certificate:  responderCert,
		Status:       ocsp.Good,
		ThisUpdate:   time.Now().AddDate(0, 0, -2),
		NextUpdate:   time.Now().AddDate(0, 0, 2),
	}
	responseBytes, _ = ocsp.CreateResponse(issuerCert, responderCert, template, priv)
	response, _ = ocsp.ParseResponse(responseBytes, issuerCert)
	err = ocsputil.VerifyAuthorizedResponder(response.Certificate, issuerCert, intermediateCerts, rootCertPool)
	assert.Nil(err)

	// Response status: revoked
	// CRITICAL: certificate has been deliberately revoked
	//     OCSP Response Data:
	//         OCSP Response Status: success (0x0)
	//         Cert Status: revoked
	//         Produced At: 2021-06-28 08:30:00 +0000 UTC
	//         Revocation Time: 2021-06-18 08:30:48 +0000 UTC
	//         Revocation Reason: keyCompromise (0x1)
	//         This Update: 2021-06-26 08:30:48 +0000 UTC
	//         Next Update: 2021-06-30 08:30:48 +0000 UTC
	//     Certificate:
	//         Issuer : CN=Intermediate CA A RSA
	//         Subject: CN=Intermediate CA A RSA OCSP Responder
	//         Validity:
	//             Not Before: 2021-06-28 06:23:10 +0000 UTC
	//             Not After : 2022-06-28 06:23:10 +0000 UTC
	//         Subject Public Key Info:
	//             Public Key Algorithm: RSA
	//                 RSA Public-Key: (2048 bit)
	//                 Modulus:
	//                     00:fe:6b:e6:fc:5a:21:e3:34:74:24:cc:73:fb:d4:
	//                     ...(omitted)
	//                 Exponent: 65537 (0x10001)
	template = ocsp.Response{
		SerialNumber:     targetCert.SerialNumber,
		Certificate:      responderCert,
		Status:           ocsp.Revoked,
		RevokedAt:        time.Now().AddDate(0, 0, -10),
		RevocationReason: ocsp.KeyCompromise,
		ThisUpdate:       time.Now().AddDate(0, 0, -2),
		NextUpdate:       time.Now().AddDate(0, 0, 2),
	}
	responseBytes, _ = ocsp.CreateResponse(issuerCert, responderCert, template, priv)
	response, _ = ocsp.ParseResponse(responseBytes, issuerCert)
	err = ocsputil.VerifyAuthorizedResponder(response.Certificate, issuerCert, intermediateCerts, rootCertPool)
	assert.Nil(err)

	// Response status: unknown
	// CRITICAL: OCSP responder doesn't know about the certificate
	//     OCSP Response Data:
	//         OCSP Response Status: success (0x0)
	//         Cert Status: unknown
	//         Produced At: 2021-06-28 08:32:00 +0000 UTC
	//         This Update: 2021-06-26 08:32:04 +0000 UTC
	//         Next Update: 2021-06-30 08:32:04 +0000 UTC
	//     Certificate:
	//         Issuer : CN=Intermediate CA A RSA
	//         Subject: CN=Intermediate CA A RSA OCSP Responder
	//         Validity:
	//             Not Before: 2021-06-28 07:56:03 +0000 UTC
	//             Not After : 2022-06-28 07:56:03 +0000 UTC
	//         Subject Public Key Info:
	//             Public Key Algorithm: RSA
	//                 RSA Public-Key: (2048 bit)
	//                 Modulus:
	//                     00:fe:6b:e6:fc:5a:21:e3:34:74:24:cc:73:fb:d4:
	//                     ...(omitted)
	//                 Exponent: 65537 (0x10001)
	template = ocsp.Response{
		SerialNumber: targetCert.SerialNumber,
		Certificate:  responderCert,
		Status:       ocsp.Unknown,
		ThisUpdate:   time.Now().AddDate(0, 0, -2),
		NextUpdate:   time.Now().AddDate(0, 0, 2),
	}
	responseBytes, _ = ocsp.CreateResponse(issuerCert, responderCert, template, priv)
	response, _ = ocsp.ParseResponse(responseBytes, issuerCert)
	err = ocsputil.VerifyAuthorizedResponder(response.Certificate, issuerCert, intermediateCerts, rootCertPool)
	assert.Nil(err)

	// expired certificate
	// Response status: good
	// CRITICAL: ocsp: OCSP response signer's certificate error: x509: certificate has expired or is not yet valid: current time 2021-06-27T21:39:00+09:00 is after 2020-01-01T00:00:00Z
	//     OCSP Response Data:
	//         OCSP Response Status: success (0x0)
	//         Cert Status: good
	//         Produced At: 2021-06-28 06:39:00 +0000 UTC
	//         This Update: 2021-06-27 06:39:22 +0000 UTC
	//         Next Update: 2021-06-29 06:39:22 +0000 UTC
	//     Certificate:
	//         Issuer : CN=Intermediate CA A RSA
	//         Subject: CN=Intermediate CA A RSA OCSP Responder
	//         Validity:
	//             Not Before: 2019-01-01 00:00:00 +0000 UTC
	//             Not After : 2020-01-01 00:00:00 +0000 UTC
	//         Subject Public Key Info:
	//             Public Key Algorithm: RSA
	//                 RSA Public-Key: (2048 bit)
	//                 Modulus:
	//                     00:fe:6b:e6:fc:5a:21:e3:34:74:24:cc:73:fb:d4:
	//                     ...(omitted)
	//                 Exponent: 65537 (0x10001)
	responderCert, _ = x509util.ParseCertificateFile("../test/testdata/pki/cert/expired/ca-intermediate-a-rsa-ocsp-responder.crt")
	template = ocsp.Response{
		SerialNumber: targetCert.SerialNumber,
		Certificate:  responderCert,
		Status:       ocsp.Good,
		ThisUpdate:   time.Now().AddDate(0, 0, -2),
		NextUpdate:   time.Now().AddDate(0, 0, 2),
	}
	responseBytes, _ = ocsp.CreateResponse(issuerCert, responderCert, template, priv)
	response, _ = ocsp.ParseResponse(responseBytes, issuerCert)
	err = ocsputil.VerifyAuthorizedResponder(response.Certificate, issuerCert, intermediateCerts, rootCertPool)
	assert.NotNil(err)
	assert.Equal(x509.InvalidReason(1), err.(x509.CertificateInvalidError).Reason)
	assert.Contains(err.(x509.CertificateInvalidError).Detail, "is after 2020-01-01T00:00:00Z")
}
