// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestNewCertificateListChecker(t *testing.T) {
	var (
		c            checker.Checker
		certs        []*x509.Certificate
		certInfo     checker.CertificateInfo
		certInfoList []checker.CertificateInfo
		err          error
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	// no certificate
	//
	// CRITICAL: no certificate
	c = checker.NewCertificateListChecker([]*x509.Certificate{})

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: no certificate")

	// valid certificate (without intermediate certificate)
	//
	// OK: certificates are valid
	//     - OK: server-a.test
	//         Subject   : CN=server-a.test
	//         Issuer    : CN=Intermediate CA A RSA
	//         Expiration: 2022-06-22 13:42:19 +0900
	certs, err = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	assert.Nil(err)
	c = checker.NewCertificateListChecker(certs)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: certificates are valid")

	w.Reset()
	c.PrintDetails()
	certInfoList = c.Details().(checker.CertificateListDetails)

	certInfo = certInfoList[0]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("server-a.test", certInfo.CommonName)
	assert.Equal("CN=server-a.test", certInfo.Subject)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Issuer)
	assert.Contains(w.String(), `    - OK: server-a.test
        Subject   : CN=server-a.test
        Issuer    : CN=Intermediate CA A RSA
        Expiration: `)

	// valid certificates
	//
	// OK: certificates are valid
	//     - OK: server-a.test
	//         Subject   : CN=server-a.test
	//         Issuer    : CN=Intermediate CA A RSA
	//         Expiration: 2022-06-22 13:42:19 +0900
	//     - OK: Intermediate CA A RSA
	//         Subject   : CN=Intermediate CA A RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2031-06-23 13:42:19 +0900
	certs, err = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	assert.Nil(err)
	c = checker.NewCertificateListChecker(certs)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: certificates are valid")

	w.Reset()
	c.PrintDetails()
	certInfoList = c.Details().(checker.CertificateListDetails)

	certInfo = certInfoList[0]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("server-a.test", certInfo.CommonName)
	assert.Equal("CN=server-a.test", certInfo.Subject)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Issuer)
	assert.Contains(w.String(), `    - OK: server-a.test
        Subject   : CN=server-a.test
        Issuer    : CN=Intermediate CA A RSA
        Expiration: `)

	certInfo = certInfoList[1]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("Intermediate CA A RSA", certInfo.CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Subject)
	assert.Equal("CN=ROOT CA G2 RSA", certInfo.Issuer)
	assert.Contains(w.String(), `    - OK: Intermediate CA A RSA
        Subject   : CN=Intermediate CA A RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	// expired server certificate
	//
	// CRITICAL: the certificate has expired on 2020-01-01 09:00:00 +0900
	//     - ERROR: server-a.test
	//         Subject   : CN=server-a.test
	//         Issuer    : CN=Intermediate CA A RSA
	//         Expiration: 2020-01-01 09:00:00 +0900
	//         Error     : the certificate has expired on 2020-01-01 09:00:00 +0900
	//     - OK: Intermediate CA A RSA
	//         Subject   : CN=Intermediate CA A RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2031-06-23 15:08:25 +0900
	certs, err = x509util.ParseCertificateFiles("../test/testdata/pki/cert/expired/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	assert.Nil(err)
	c = checker.NewCertificateListChecker(certs)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: the certificate has expired on ")

	w.Reset()
	c.PrintDetails()
	certInfoList = c.Details().(checker.CertificateListDetails)

	certInfo = certInfoList[0]
	assert.Equal(checker.ERROR, certInfo.Status)
	assert.Equal("server-a.test", certInfo.CommonName)
	assert.Equal("CN=server-a.test", certInfo.Subject)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Issuer)
	assert.Contains(w.String(), `    - ERROR: server-a.test
        Subject   : CN=server-a.test
        Issuer    : CN=Intermediate CA A RSA
        Expiration: `)

	certInfo = certInfoList[1]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("Intermediate CA A RSA", certInfo.CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Subject)
	assert.Equal("CN=ROOT CA G2 RSA", certInfo.Issuer)
	assert.Contains(w.String(), `    - OK: Intermediate CA A RSA
        Subject   : CN=Intermediate CA A RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	// expired intermediate certificate
	//
	// CRITICAL: the certificate has expired on 2020-01-01 09:00:00 +0900
	//     - OK: server-a.test
	//         Subject   : CN=server-a.test
	//         Issuer    : CN=Intermediate CA A RSA
	//         Expiration: 2022-06-22 15:08:25 +0900
	//     - ERROR: Intermediate CA A RSA
	//         Subject   : CN=Intermediate CA A RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2020-01-01 09:00:00 +0900
	//         Error     : the certificate has expired on 2020-01-01 09:00:00 +0900
	certs, err = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/expired/ca-intermediate-a-rsa.crt")
	assert.Nil(err)
	c = checker.NewCertificateListChecker(certs)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: the certificate has expired on ")

	w.Reset()
	c.PrintDetails()
	certInfoList = c.Details().(checker.CertificateListDetails)

	certInfo = certInfoList[0]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("server-a.test", certInfo.CommonName)
	assert.Equal("CN=server-a.test", certInfo.Subject)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Issuer)
	assert.Contains(w.String(), `    - OK: server-a.test
        Subject   : CN=server-a.test
        Issuer    : CN=Intermediate CA A RSA
        Expiration: `)

	certInfo = certInfoList[1]
	assert.Equal(checker.ERROR, certInfo.Status)
	assert.Equal("Intermediate CA A RSA", certInfo.CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Subject)
	assert.Equal("CN=ROOT CA G2 RSA", certInfo.Issuer)
	assert.Contains(w.String(), `    - ERROR: Intermediate CA A RSA
        Subject   : CN=Intermediate CA A RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

	// invalid parent intermediate certificate
	//
	// CRITICAL: crypto/rsa: verification error / parent certificate may not be correct issuer
	//     - ERROR: server-b.test
	//         Subject   : CN=server-b.test
	//         Issuer    : CN=Intermediate CA B RSA
	//         Expiration: 2022-06-22 15:08:25 +0900
	//         Error     : x509: issuer name does not match subject from issuing certificate / crypto/rsa: verification error / parent certificate may not be correct issuer
	//     - OK: Intermediate CA A RSA
	//         Subject   : CN=Intermediate CA A RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2031-06-23 15:08:25 +0900
	certs, err = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	assert.Nil(err)
	c = checker.NewCertificateListChecker(certs)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: x509: issuer name does not match subject from issuing certificate / crypto/rsa: verification error / parent certificate may not be correct issuer")

	w.Reset()
	c.PrintDetails()
	certInfoList = c.Details().(checker.CertificateListDetails)

	certInfo = certInfoList[0]
	assert.Equal(checker.ERROR, certInfo.Status)
	assert.Equal("server-b.test", certInfo.CommonName)
	assert.Equal("CN=server-b.test", certInfo.Subject)
	assert.Equal("CN=Intermediate CA B RSA", certInfo.Issuer)
	assert.Contains(w.String(), `    - ERROR: server-b.test
        Subject   : CN=server-b.test
        Issuer    : CN=Intermediate CA B RSA
        Expiration: `)

	certInfo = certInfoList[1]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("Intermediate CA A RSA", certInfo.CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Subject)
	assert.Equal("CN=ROOT CA G2 RSA", certInfo.Issuer)
	assert.Contains(w.String(), `    - OK: Intermediate CA A RSA
        Subject   : CN=Intermediate CA A RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

}

func TestCertificateListChecker(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	certs, err := x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	assert.Nil(err)
	c := checker.NewCertificateListChecker(certs)
	assert.Equal("Peer Certificate List", c.Name())
	assert.Equal(checker.OK, c.Status())
	assert.Equal("certificates are valid", c.Message())
	assert.Equal("server-a.test", c.Details().(checker.CertificateListDetails)[0].CommonName)

	c.PrintName()
	assert.Equal("[Peer Certificate List]\n", w.String())

	w.Reset()
	c.PrintStatus()
	assert.Equal("OK: certificates are valid\n", w.String())

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    - OK: server-a.test
        Subject   : CN=server-a.test
        Issuer    : CN=Intermediate CA A RSA
        Expiration: `)
}
