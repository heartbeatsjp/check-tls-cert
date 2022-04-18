// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"strings"
	"testing"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestNewHostnameChecker(t *testing.T) {
	var (
		c checker.Checker
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	// Subject: CN=server-a.test
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	cert := certs[0]

	// empty hostname
	//
	// CRITICAL: the hostname '' is invalid for the certificate
	//     Common Name: server-a.test
	//     Subject Alternative Name:
	//         DNS: server-a.test
	//         DNS: www.server-a.test
	c = checker.NewHostnameChecker("", cert)

	w.Reset()
	c.PrintStatus()
	assert.EqualValues(checker.CRITICAL, c.Status())
	assert.Contains(c.Message(), "the hostname '' is invalid for the certificate")
	assert.Contains(w.String(), "CRITICAL: the hostname '' is invalid for the certificate")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Common Name: server-a.test
    Subject Alternative Name:
        DNS: server-a.test
        DNS: www.server-a.test`)

	// invalid hostname
	//
	// CRITICAL: the hostname 'server-b.test' is invalid for the certificate / x509: certificate is valid for server-a.test, www.server-a.test, not server-b.test
	//     Common Name: server-a.test
	//     Subject Alternative Name:
	//         DNS: server-a.test
	//         DNS: www.server-a.test
	c = checker.NewHostnameChecker("server-b.test", cert)

	w.Reset()
	c.PrintStatus()
	assert.EqualValues(checker.CRITICAL, c.Status())
	assert.Contains(c.Message(), "the hostname 'server-b.test' is invalid for the certificate")
	assert.Contains(w.String(), "CRITICAL: the hostname 'server-b.test' is invalid for the certificate")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Common Name: server-a.test
    Subject Alternative Name:
        DNS: server-a.test
        DNS: www.server-a.test`)

	// valid hostname
	//
	// OK: the hostname 'server-a.test' is valid for the certificate
	//     Common Name: server-a.test
	//     Subject Alternative Name:
	//         DNS: server-a.test
	//         DNS: www.server-a.test
	c = checker.NewHostnameChecker("server-a.test", cert)

	w.Reset()
	c.PrintStatus()
	assert.EqualValues(checker.OK, c.Status())
	assert.EqualValues("the hostname 'server-a.test' is valid for the certificate", c.Message())
	assert.Contains(w.String(), "OK: the hostname 'server-a.test' is valid for the certificate")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Common Name: server-a.test
    Subject Alternative Name:
        DNS: server-a.test
        DNS: www.server-a.test`)

}

func TestHostnameChecker(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	cert, _ := x509util.ParseCertificateFile("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	c := checker.NewHostnameChecker("server-a.test", cert)
	assert.Equal("Hostname", c.Name())
	assert.Equal(checker.OK, c.Status())
	assert.Equal("the hostname 'server-a.test' is valid for the certificate", c.Message())
	assert.Equal("server-a.test", c.Details().(*checker.HostnameDetails).CommonName)

	c.PrintName()
	assert.Equal("[Hostname]\n", w.String())

	w.Reset()
	c.PrintStatus()
	assert.Equal("OK: the hostname 'server-a.test' is valid for the certificate\n", w.String())

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    Common Name: server-a.test
    Subject Alternative Name:
        DNS: server-a.test
        DNS: www.server-a.test`)
}
