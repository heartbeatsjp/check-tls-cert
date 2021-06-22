// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/x509"
	"strings"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckHostname(t *testing.T) {
	var state checker.State
	w := strings.Builder{}
	checker.SetOutput(&w)
	assert := assert.New(t)

	// Subject: CN=server-a.test
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	cert := certs[0]

	// empty hostname
	//
	// CRITICAL: the hostname '' is invalid for the certificate
	//     Common Name: server-a.test
	//     Subject Alternative Names:
	//         DNS: server-a.test
	//         DNS: www.server-a.test
	state = checker.CheckHostname("", cert)
	w.Reset()
	state.Print()
	assert.EqualValues(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the hostname '' is invalid for the certificate")
	assert.Contains(w.String(), "CRITICAL: the hostname '' is invalid for the certificate")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.EqualValues("CN=server-a.test", state.Data.(*x509.Certificate).Subject.String())
	assert.EqualValues([]string{"server-a.test", "www.server-a.test"}, state.Data.(*x509.Certificate).DNSNames)
	assert.Contains(w.String(), `    Common Name: server-a.test
    Subject Alternative Names:
        DNS: server-a.test
        DNS: www.server-a.test`)

	// invalid hostname
	//
	// CRITICAL: the hostname 'server-b.test' is invalid for the certificate / x509: certificate is valid for server-a.test, www.server-a.test, not server-b.test
	//     Common Name: server-a.test
	//     Subject Alternative Names:
	//         DNS: server-a.test
	//         DNS: www.server-a.test
	state = checker.CheckHostname("server-b.test", cert)
	w.Reset()
	state.Print()
	assert.EqualValues(checker.CRITICAL, state.Status)
	assert.Contains(state.Message, "the hostname 'server-b.test' is invalid for the certificate")
	assert.Contains(w.String(), "CRITICAL: the hostname 'server-b.test' is invalid for the certificate")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.EqualValues("CN=server-a.test", state.Data.(*x509.Certificate).Subject.String())
	assert.EqualValues([]string{"server-a.test", "www.server-a.test"}, state.Data.(*x509.Certificate).DNSNames)
	assert.Contains(w.String(), `    Common Name: server-a.test
    Subject Alternative Names:
        DNS: server-a.test
        DNS: www.server-a.test`)

	// valid hostname
	//
	// OK: the hostname 'server-a.test' is valid for the certificate
	//     Common Name: server-a.test
	//     Subject Alternative Names:
	//         DNS: server-a.test
	//         DNS: www.server-a.test
	state = checker.CheckHostname("server-a.test", cert)
	w.Reset()
	state.Print()
	assert.EqualValues(checker.OK, state.Status)
	assert.EqualValues("the hostname 'server-a.test' is valid for the certificate", state.Message)
	assert.Contains(w.String(), "OK: the hostname 'server-a.test' is valid for the certificate")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.EqualValues("CN=server-a.test", state.Data.(*x509.Certificate).Subject.String())
	assert.EqualValues([]string{"server-a.test", "www.server-a.test"}, state.Data.(*x509.Certificate).DNSNames)
	assert.Contains(w.String(), `    Common Name: server-a.test
    Subject Alternative Names:
        DNS: server-a.test
        DNS: www.server-a.test`)

}
