// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ocsp"
)

func TestCheckOCSPStapling(t *testing.T) {
	var (
		state    checker.State
		template ocsp.Response
		response []byte
	)
	w := strings.Builder{}
	checker.SetOutput(&w)
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
	state = checker.CheckOCSPStapling([]byte{}, nil, intermediateCerts, rootCertPool, true)
	assert.Equal(checker.INFO, state.Status)
	assert.Equal("no response sent", state.Message)
	w.Reset()
	state.Print()
	assert.Equal(w.String(), "INFO: no response sent\n")

	// no response
	state = checker.CheckOCSPStapling([]byte{}, issuerCert, intermediateCerts, rootCertPool, true)
	assert.Equal(checker.INFO, state.Status)
	assert.Equal("no response sent", state.Message)
	w.Reset()
	state.Print()
	assert.Equal(w.String(), "INFO: no response sent\n")

	// no response
	state = checker.CheckOCSPStapling([]byte{}, issuerCert, intermediateCerts, rootCertPool, false)
	assert.Equal(checker.WARNING, state.Status)
	assert.Equal("ocsp: no response sent", state.Message)
	w.Reset()
	state.Print()
	assert.Equal(w.String(), "WARNING: ocsp: no response sent\n")

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
	response, _ = ocsp.CreateResponse(issuerCert, responderCert, template, priv)
	state = checker.CheckOCSPStapling(response, issuerCert, intermediateCerts, rootCertPool, true)
	assert.Equal(checker.OK, state.Status)
	assert.Equal("certificate is valid", state.Message)

	w.Reset()
	state.Print()
	assert.Equal(w.String(), "OK: certificate is valid\n")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Contains(w.String(), `    OCSP Response Data:
        OCSP Response Status: successful (0x0)
        Cert Status: good
`)
	assert.Contains(w.String(), `    Certificate:
        Issuer : CN=Intermediate CA A RSA
        Subject: CN=Intermediate CA A RSA OCSP Responder
        Validity:
`)

	// Response statu: revoked
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
		SerialNumber:     targetCert.SerialNumber,
		Certificate:      responderCert,
		Status:           ocsp.Revoked,
		RevokedAt:        time.Now().AddDate(0, 0, -10),
		RevocationReason: ocsp.KeyCompromise,
		ThisUpdate:       time.Now().AddDate(0, 0, -2),
		NextUpdate:       time.Now().AddDate(0, 0, 2),
	}
	response, _ = ocsp.CreateResponse(issuerCert, responderCert, template, priv)
	state = checker.CheckOCSPStapling(response, issuerCert, intermediateCerts, rootCertPool, true)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Equal("certificate has been deliberately revoked", state.Message)

	w.Reset()
	state.Print()
	assert.Equal(w.String(), "CRITICAL: certificate has been deliberately revoked\n")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Contains(w.String(), `    OCSP Response Data:
        OCSP Response Status: successful (0x0)
        Cert Status: revoked
`)
	assert.Contains(w.String(), `        Revocation Time: `)
	assert.Contains(w.String(), `        Revocation Reason: keyCompromise (0x1)`)
	assert.Contains(w.String(), `    Certificate:
        Issuer : CN=Intermediate CA A RSA
        Subject: CN=Intermediate CA A RSA OCSP Responder
        Validity:
`)

	// Response statu: unknown
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
	response, _ = ocsp.CreateResponse(issuerCert, responderCert, template, priv)
	state = checker.CheckOCSPStapling(response, issuerCert, intermediateCerts, rootCertPool, true)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Equal("OCSP responder doesn't know about the certificate", state.Message)

	w.Reset()
	state.Print()
	assert.Equal(w.String(), "CRITICAL: OCSP responder doesn't know about the certificate\n")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Contains(w.String(), `    OCSP Response Data:
        OCSP Response Status: successful (0x0)
        Cert Status: unknown
`)
	assert.Contains(w.String(), `    Certificate:
        Issuer : CN=Intermediate CA A RSA
        Subject: CN=Intermediate CA A RSA OCSP Responder
        Validity:
`)

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
	response, _ = ocsp.CreateResponse(issuerCert, responderCert, template, priv)
	state = checker.CheckOCSPStapling(response, issuerCert, intermediateCerts, rootCertPool, true)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "ocsp: OCSP response signer's certificate error: x509: certificate has expired or is not yet valid:")

	w.Reset()
	state.Print()
	assert.Contains(w.String(), "CRITICAL: ocsp: OCSP response signer's certificate error: x509: certificate has expired or is not yet valid:")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Contains(w.String(), `    OCSP Response Data:
        OCSP Response Status: successful (0x0)
        Cert Status: good
`)
	assert.Contains(w.String(), `    Certificate:
        Issuer : CN=Intermediate CA A RSA
        Subject: CN=Intermediate CA A RSA OCSP Responder
        Validity:
`)
}
