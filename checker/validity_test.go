// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckValidity(t *testing.T) {
	var state checker.State
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

	state = checker.CheckValidity(cert, 0, 0)
	assert.Equal(checker.OK, state.Status)
	assert.Contains(state.Message, "the certificate will expire in")

	state = checker.CheckValidity(cert, 28, 14)
	assert.Equal(checker.OK, state.Status)
	assert.Contains(state.Message, "the certificate will expire in")

	state = checker.CheckValidity(cert, 366, 364)
	assert.Equal(checker.WARNING, state.Status)
	assert.Contains(state.Message, "the certificate will expire in")

	state = checker.CheckValidity(cert, 368, 366)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate will expire in")

	state = checker.CheckValidity(expiredCert, 0, 0)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate has expired on")

	state = checker.CheckValidity(expiredCert, 10000, 10000)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate has expired on")

	state = checker.CheckValidity(notYetValidCert, 0, 0)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate is not yet valid and will be valid on")

	state = checker.CheckValidity(notYetValidCert, 10000, 10000)
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the certificate is not yet valid and will be valid on")
}
