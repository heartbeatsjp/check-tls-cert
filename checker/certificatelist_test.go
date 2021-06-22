// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"crypto/x509"
	"log"
	"strings"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckCertificateList(t *testing.T) {
	var (
		state    checker.State
		certs    []*x509.Certificate
		certInfo checker.CertificateInfo
		err      error
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)

	// no certificate
	//
	// CRITICAL: no certificate
	state = checker.CheckCertificateList([]*x509.Certificate{})

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: no certificate")

	// valid certificate (without intermediate certificate)
	//
	// OK: certificates are valid
	//     - OK: server-a.test
	//         Subject   : CN=server-a.test
	//         Issuer    : CN=Intermediate CA A RSA
	//         Expiration: 2022-06-22 13:42:19 +0900
	certs, err = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-a-rsa.crt")
	if err != nil {
		log.Print(err)
	}
	state = checker.CheckCertificateList(certs)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: certificates are valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	certInfo = state.Data.([]checker.CertificateInfo)[0]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("server-a.test", certInfo.CommonName)
	assert.Equal("CN=server-a.test", certInfo.Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Certificate.Issuer.String())
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
	if err != nil {
		log.Print(err)
	}
	state = checker.CheckCertificateList(certs)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: certificates are valid")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	certInfo = state.Data.([]checker.CertificateInfo)[0]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("server-a.test", certInfo.CommonName)
	assert.Equal("CN=server-a.test", certInfo.Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: server-a.test
        Subject   : CN=server-a.test
        Issuer    : CN=Intermediate CA A RSA
        Expiration: `)

	certInfo = state.Data.([]checker.CertificateInfo)[1]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("Intermediate CA A RSA", certInfo.CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", certInfo.Certificate.Issuer.String())
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
	if err != nil {
		log.Print(err)
	}
	state = checker.CheckCertificateList(certs)

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: the certificate has expired on ")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	certInfo = state.Data.([]checker.CertificateInfo)[0]
	assert.Equal(checker.ERROR, certInfo.Status)
	assert.Equal("server-a.test", certInfo.CommonName)
	assert.Equal("CN=server-a.test", certInfo.Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Certificate.Issuer.String())
	assert.Contains(w.String(), `    - ERROR: server-a.test
        Subject   : CN=server-a.test
        Issuer    : CN=Intermediate CA A RSA
        Expiration: `)

	certInfo = state.Data.([]checker.CertificateInfo)[1]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("Intermediate CA A RSA", certInfo.CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", certInfo.Certificate.Issuer.String())
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
	if err != nil {
		log.Print(err)
	}
	state = checker.CheckCertificateList(certs)

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: the certificate has expired on ")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	certInfo = state.Data.([]checker.CertificateInfo)[0]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("server-a.test", certInfo.CommonName)
	assert.Equal("CN=server-a.test", certInfo.Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: server-a.test
        Subject   : CN=server-a.test
        Issuer    : CN=Intermediate CA A RSA
        Expiration: `)

	certInfo = state.Data.([]checker.CertificateInfo)[1]
	assert.Equal(checker.ERROR, certInfo.Status)
	assert.Equal("Intermediate CA A RSA", certInfo.CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", certInfo.Certificate.Issuer.String())
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
	//         Error     : crypto/rsa: verification error / parent certificate may not be correct issuer
	//     - OK: Intermediate CA A RSA
	//         Subject   : CN=Intermediate CA A RSA
	//         Issuer    : CN=ROOT CA G2 RSA
	//         Expiration: 2031-06-23 15:08:25 +0900
	certs, err = x509util.ParseCertificateFiles("../test/testdata/pki/cert/valid/server-b-rsa.crt", "../test/testdata/pki/cert/valid/ca-intermediate-a-rsa.crt")
	if err != nil {
		log.Print(err)
	}
	state = checker.CheckCertificateList(certs)

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: crypto/rsa: verification error / parent certificate may not be correct issuer")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	certInfo = state.Data.([]checker.CertificateInfo)[0]
	assert.Equal(checker.ERROR, certInfo.Status)
	assert.Equal("server-b.test", certInfo.CommonName)
	assert.Equal("CN=server-b.test", certInfo.Certificate.Subject.String())
	assert.Equal("CN=Intermediate CA B RSA", certInfo.Certificate.Issuer.String())
	assert.Contains(w.String(), `    - ERROR: server-b.test
        Subject   : CN=server-b.test
        Issuer    : CN=Intermediate CA B RSA
        Expiration: `)

	certInfo = state.Data.([]checker.CertificateInfo)[1]
	assert.Equal(checker.OK, certInfo.Status)
	assert.Equal("Intermediate CA A RSA", certInfo.CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certInfo.Certificate.Subject.String())
	assert.Equal("CN=ROOT CA G2 RSA", certInfo.Certificate.Issuer.String())
	assert.Contains(w.String(), `    - OK: Intermediate CA A RSA
        Subject   : CN=Intermediate CA A RSA
        Issuer    : CN=ROOT CA G2 RSA
        Expiration: `)

}
