// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/x509"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckHostname(t *testing.T) {
	var state checker.State
	assert := assert.New(t)

	// Subject: CN=server-a.test
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	cert := certs[0]

	state = checker.CheckHostname("", cert)
	assert.EqualValues(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the hostname '' is invalid for the certificate")
	assert.EqualValues("CN=server-a.test", state.Data.(*x509.Certificate).Subject.String())
	assert.EqualValues([]string{"server-a.test", "www.server-a.test"}, state.Data.(*x509.Certificate).DNSNames)

	state = checker.CheckHostname("server-b.test", cert)
	assert.EqualValues(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the hostname 'server-b.test' is invalid for the certificate")
	assert.EqualValues("CN=server-a.test", state.Data.(*x509.Certificate).Subject.String())
	assert.EqualValues([]string{"server-a.test", "www.server-a.test"}, state.Data.(*x509.Certificate).DNSNames)

	state = checker.CheckHostname("server-a.test", cert)
	assert.EqualValues(checker.OK, state.Status)
	assert.EqualValues("the hostname 'server-a.test' is valid for the certificate", state.Message)
	assert.EqualValues("CN=server-a.test", state.Data.(*x509.Certificate).Subject.String())
	assert.EqualValues([]string{"server-a.test", "www.server-a.test"}, state.Data.(*x509.Certificate).DNSNames)
}
