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

func TestVerbose(t *testing.T) {
	assert := assert.New(t)

	checker.SetVerbose(1)
	assert.Equal(1, checker.GetVerbose())
}

func TestDNType(t *testing.T) {
	assert := assert.New(t)

	checker.SetDNType(x509util.StrictDN)
	assert.Equal(x509util.StrictDN, checker.GetDNType())
}

func TestCurrentTime(t *testing.T) {
	assert := assert.New(t)

	now := time.Now()
	checker.SetCurrentTime(now)
	assert.Equal(now, checker.GetCurrentTime())
}

func TestStatusPrint(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)

	checker.Print("TEST")
	assert.Equal("TEST", w.String())
}

func TestStatusPrintf(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)

	checker.Printf("TEST: %s", "VALUE")
	assert.Equal("TEST: VALUE", w.String())
}

func TestStatusPrintln(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)

	checker.Println("TEST")
	assert.Equal("TEST\n", w.String())
}

func TestStatusCode(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(0, checker.OK.Code())
	assert.Equal(1, checker.WARNING.Code())
	assert.Equal(2, checker.CRITICAL.Code())
	assert.Equal(3, checker.UNKNOWN.Code())
}

func TestStatusString(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("OK", checker.OK.String())
	assert.Equal("WARNING", checker.WARNING.String())
	assert.Equal("CRITICAL", checker.CRITICAL.String())
	assert.Equal("UNKNOWN", checker.UNKNOWN.String())
}

func TestResultPrint(t *testing.T) {
	var (
		checkerList []checker.Checker
		c           checker.Checker
		summary     *checker.Summary
		result      *checker.Result
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(3)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	// This certificate will expire in 365 days.
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	cert := certs[0]

	// OK: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 0, 0)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	result = checker.NewResult(summary, checkerList)

	w.Reset()
	result.Print()
	assert.Contains(w.String(), "OK: all checks have been passed\n")

	// WARNING: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 366, 364)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	result = checker.NewResult(summary, checkerList)

	w.Reset()
	result.Print()
	assert.Contains(w.String(), "WARNING: the certificate will expire ")

	// CRITICAL: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 368, 366)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	result = checker.NewResult(summary, checkerList)

	w.Reset()
	result.Print()
	assert.Contains(w.String(), "CRITICAL: the certificate will expire ")

	// verbose = 0
	checker.SetVerbose(0)
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 0, 0)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	result = checker.NewResult(summary, checkerList)
	w.Reset()
	result.Print()
	assert.Equal("OK: all checks have been passed\n", w.String())

	// verbose = 1
	checker.SetVerbose(1)
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 0, 0)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	result = checker.NewResult(summary, checkerList)
	w.Reset()
	result.Print()
	assert.Contains(w.String(), "OK: all checks have been passed\n")
	assert.Contains(w.String(), "[Summary]\n")
	assert.Contains(w.String(), "To get more detailed information, use the '-vv' option.\n")

	// verbose = 2
	checker.SetVerbose(2)
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 0, 0)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	result = checker.NewResult(summary, checkerList)
	w.Reset()
	result.Print()
	assert.Contains(w.String(), "OK: all checks have been passed\n")
	assert.Contains(w.String(), "[Summary]\n")
	assert.Contains(w.String(), "To get more detailed information, use the '-vvv' option.\n")

	// verbose = 3
	checker.SetVerbose(3)
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 0, 0)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	result = checker.NewResult(summary, checkerList)
	w.Reset()
	result.Print()
	assert.Contains(w.String(), "OK: all checks have been passed\n")
	assert.Contains(w.String(), "[Summary]\n")
	assert.NotContains(w.String(), "To get more detailed information,")
}

func TestResultPrintJSON(t *testing.T) {
	var (
		checkerList []checker.Checker
		c           checker.Checker
		summary     *checker.Summary
		result      *checker.Result
	)
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
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 0, 0)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	result = checker.NewResult(summary, checkerList)

	w.Reset()
	result.PrintJSON()
	assert.Contains(w.String(), `{
  "metadata": {
    "name": "check-tls-cert",
    "timestamp": "`)
	assert.Contains(w.String(), `",
    "command": "`)
	assert.Contains(w.String(), `",
    "status": 0`)
	assert.Contains(w.String(), `  },
  "result": {
    "summary": {
      "name": "Summary",
      "status": "OK",
      "message": "all checks have been passed"
    },`)
	assert.Contains(w.String(), `,
    "checkers": [
      {
        "name": "Validity",
        "status": "OK",
        "message": "the certificate will expire in `)
}
