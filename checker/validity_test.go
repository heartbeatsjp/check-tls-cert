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

func TestNewValidityChecker(t *testing.T) {
	var c checker.Checker
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

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
	c = checker.NewValidityChecker(cert, 0, 0)
	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(c.Message(), "the certificate will expire in ")
	assert.Contains(w.String(), "OK: the certificate will expire in ")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), "    Not Before: ")
	assert.Contains(w.String(), "    Not After : ")

	// OK: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	c = checker.NewValidityChecker(cert, 28, 14)
	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(c.Message(), "the certificate will expire in ")
	assert.Contains(w.String(), "OK: the certificate will expire in ")

	// WARNING: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	c = checker.NewValidityChecker(cert, 366, 364)
	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.WARNING, c.Status())
	assert.Contains(c.Message(), "the certificate will expire in")
	assert.Contains(w.String(), "WARNING: the certificate will expire in ")

	// CRITICAL: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	c = checker.NewValidityChecker(cert, 368, 366)
	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(c.Message(), "the certificate will expire in")
	assert.Contains(w.String(), "CRITICAL: the certificate will expire in ")

	// CRITICAL: the certificate has expired on 2020-01-01 09:00:00 +0900
	c = checker.NewValidityChecker(expiredCert, 0, 0)
	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(c.Message(), "the certificate has expired on")
	assert.Contains(w.String(), "CRITICAL: the certificate has expired on ")

	// CRITICAL: the certificate has expired on 2020-01-01 09:00:00 +0900
	c = checker.NewValidityChecker(expiredCert, 10000, 10000)
	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(c.Message(), "the certificate has expired on")
	assert.Contains(w.String(), "CRITICAL: the certificate has expired on ")

	// CRITICAL: the certificate is not yet valid and will be valid on 2035-01-01 09:00:00 +0900
	c = checker.NewValidityChecker(notYetValidCert, 0, 0)
	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(c.Message(), "the certificate is not yet valid and will be valid on ")
	assert.Contains(w.String(), "CRITICAL: the certificate is not yet valid and will be valid on ")

	// CRITICAL: the certificate is not yet valid and will be valid on 2035-01-01 09:00:00 +0900
	c = checker.NewValidityChecker(notYetValidCert, 10000, 10000)
	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(c.Message(), "the certificate is not yet valid and will be valid on ")
	assert.Contains(w.String(), "CRITICAL: the certificate is not yet valid and will be valid on ")
}

func TestValidityChecker(t *testing.T) {
	var c checker.Checker
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	// This certificate will expire in 365 days.
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	cert := certs[0]

	// OK: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	//     Not Before: 2021-06-22 16:10:14 +0900
	//     Not After : 2022-06-22 16:10:14 +0900
	c = checker.NewValidityChecker(cert, 0, 0)
	assert.Equal("Validity", c.Name())
	assert.Equal(checker.OK, c.Status())
	assert.Contains(c.Message(), "the certificate will expire in ")
	assert.Regexp("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [-+][0-9]{4}( UTC)?", c.Details().(*checker.ValidityDetails).NotBefore)
	assert.Regexp("[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} [-+][0-9]{4}( UTC)?", c.Details().(*checker.ValidityDetails).NotAfter)

	c.PrintName()
	assert.Equal("[Validity]\n", w.String())

	w.Reset()
	c.PrintStatus()
	assert.Contains(w.String(), "OK: the certificate will expire in ")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), "    Not Before: ")
	assert.Contains(w.String(), "    Not After : ")
}
