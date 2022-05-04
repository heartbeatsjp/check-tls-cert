// Copyright 2022 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestNewSummary(t *testing.T) {
	var (
		checkerList []checker.Checker
		c           checker.Checker
		summary     *checker.Summary
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	// This certificate will expire in 365 days.
	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	cert := certs[0]

	// OK: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 0, 0)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	assert.Equal(checker.OK, summary.Status())
	assert.Equal("all checks have been passed", summary.Message())

	w.Reset()
	summary.PrintStatus()
	assert.Equal("OK: all checks have been passed\n", w.String())

	// WARNING: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 366, 364)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	assert.Equal(checker.WARNING, summary.Status())
	assert.Contains(summary.Message(), "the certificate will expire in ")

	w.Reset()
	summary.PrintStatus()
	assert.Contains(w.String(), "WARNING: the certificate will expire ")

	// CRITICAL: the certificate will expire in 365 days on 2022-06-22 16:10:14 +0900
	checkerList = []checker.Checker{}
	c = checker.NewValidityChecker(cert, 368, 366)
	checkerList = append(checkerList, c)
	summary = checker.NewSummary(checkerList)
	assert.Equal(checker.CRITICAL, summary.Status())
	assert.Contains(summary.Message(), "the certificate will expire in ")

	w.Reset()
	summary.PrintStatus()
	assert.Contains(w.String(), "CRITICAL: the certificate will expire ")
}

func TestNewErrorSummary(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	summary := checker.NewErrorSummary(errors.New("error message"))
	assert.Equal(checker.UNKNOWN, summary.Status())
	assert.Equal("error message", summary.Message())

	w.Reset()
	summary.PrintStatus()
	assert.Equal("UNKNOWN: error message\n", w.String())
}

func TestSummary(t *testing.T) {
	var (
		checkerList []checker.Checker
		c           checker.Checker
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	certFile := "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	certs, _ := x509util.ParseCertificateFiles(certFile)
	cert := certs[0]

	c = checker.NewValidityChecker(cert, 0, 0)
	checkerList = append(checkerList, c)

	summary := checker.NewSummary(checkerList)
	assert.Equal("Summary", summary.Name())
	assert.Equal(checker.OK, summary.Status())
	assert.Equal("all checks have been passed", summary.Message())
	assert.Nil(summary.Details())

	w.Reset()
	summary.PrintName()
	assert.Equal("[Summary]\n", w.String())

	w.Reset()
	summary.PrintStatus()
	assert.Equal("OK: all checks have been passed\n", w.String())

	w.Reset()
	summary.PrintDetails()
	assert.Equal("", w.String())
}
