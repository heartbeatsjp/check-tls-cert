// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"strings"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckValidity(t *testing.T) {
	var state checker.State
	w := strings.Builder{}
	checker.SetOutput(&w)
	assert := assert.New(t)

	// This certificate will expire in 365 days.
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	cert := certs[0]

	// This certificate has expired.
	expiredCertFile := "../test/testdata/pki/cert/expired/server-a-rsa.crt"
	expiredCerts, _ := x509util.ParseCertificateFiles(expiredCertFile)
	expiredCert := expiredCerts[0]

	// This certificate is not yet valid.
	notYetValidCertFile := "../test/testdata/pki/cert/notyetvalid/server-a-rsa.crt"
	notYetValidCerts, _ := x509util.ParseCertificateFiles(notYetValidCertFile)
	notYetValidCert := notYetValidCerts[0]

	// OK: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	//     Not Before: 2021-06-22 16:10:14 +0900
	//     Not After : 2022-06-22 16:10:14 +0900
	state = checker.CheckValidity(cert, 0, 0)
	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(state.Message, "the certificate will expire in ")
	assert.Contains(w.String(), "OK: the certificate will expire in ")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Contains(w.String(), "    Not Before: ")
	assert.Contains(w.String(), "    Not After : ")

	// OK: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	state = checker.CheckValidity(cert, 28, 14)
	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(state.Message, "the certificate will expire in ")
	assert.Contains(w.String(), "OK: the certificate will expire in ")

	// WARNING: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	state = checker.CheckValidity(cert, 366, 364)
	w.Reset()
	state.Print()
	assert.Equal(checker.WARNING, state.Status)
	assert.Contains(state.Message, "the certificate will expire in")
	assert.Contains(w.String(), "WARNING: the certificate will expire in ")

	// CRITICAL: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	state = checker.CheckValidity(cert, 368, 366)
	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate will expire in")
	assert.Contains(w.String(), "CRITICAL: the certificate will expire in ")

	// CRITICAL: the certificate has expired on 2020-01-01 09:00:00 +0900
	state = checker.CheckValidity(expiredCert, 0, 0)
	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate has expired on")
	assert.Contains(w.String(), "CRITICAL: the certificate has expired on ")

	// CRITICAL: the certificate has expired on 2020-01-01 09:00:00 +0900
	state = checker.CheckValidity(expiredCert, 10000, 10000)
	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate has expired on")
	assert.Contains(w.String(), "CRITICAL: the certificate has expired on ")

	// CRITICAL: the certificate is not yet valid and will be valid on 2035-01-01 09:00:00 +0900
	state = checker.CheckValidity(notYetValidCert, 0, 0)
	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate is not yet valid and will be valid on ")
	assert.Contains(w.String(), "CRITICAL: the certificate is not yet valid and will be valid on ")

	// CRITICAL: the certificate is not yet valid and will be valid on 2035-01-01 09:00:00 +0900
	state = checker.CheckValidity(notYetValidCert, 10000, 10000)
	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate is not yet valid and will be valid on ")
	assert.Contains(w.String(), "CRITICAL: the certificate is not yet valid and will be valid on ")
}
