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

func TestNewCertificateFilesChecker(t *testing.T) {
	var (
		c                checker.Checker
		certFileInfoList []checker.CertificateFileInfo
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	nonExistentFile := "../test/testdata/pki/misc/non-existent.pem"
	emptyFile := "../test/testdata/pki/misc/empty.pem"
	expiredServerCertFile := "../test/testdata/pki/cert/expired/server-a-rsa.pem"
	serverCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	chainCertFile := "../test/testdata/pki/chain/chain-a-rsa.pem"
	caCertFile := "../test/testdata/pki/chain/ca.pem"
	rootCertFile := "../test/testdata/pki/root-ca/ca-root.pem"

	// Non-existent file
	//
	// CRITICAL: open ../test/testdata/pki/misc/non-existent.pem: no such file or directory
	//     ERROR: Certificate File
	//         File: ../test/testdata/pki/misc/non-existent.pem
	//         Error: open ../test/testdata/pki/misc/non-existent.pem: no such file or directory
	c = checker.NewCertificateFilesChecker(nonExistentFile, "", "", "")

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: open ../test/testdata/pki/misc/non-existent.pem: no such file or directory")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    ERROR: Certificate File
        File: ../test/testdata/pki/misc/non-existent.pem
        Error: open ../test/testdata/pki/misc/non-existent.pem: no such file or directory`)

	// Empty file
	//
	// CRITICAL: no valid certificates
	//     ERROR: Certificate File
	//         File: ../test/testdata/pki/misc/empty.pem
	//         Error: no valid certificates
	c = checker.NewCertificateFilesChecker(emptyFile, "", "", "")

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: no valid certificates")

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    ERROR: Certificate File
        File: ../test/testdata/pki/misc/empty.pem
        Error: no valid certificates`)

	// Intermediate and root certificates not found
	// Returns OK because the certificate path is not validated.
	//
	// OK: all files contain one or more certificates
	//     OK: Certificate File
	//         File: ../test/testdata/pki/cert/valid/server-a-rsa.pem
	//         Certificate:
	//             - OK: server-a.test
	//               Subject   : CN=server-a.test
	//               Issuer    : CN=Intermediate CA A RSA
	//               Expiration: 2022-06-21 12:16:35 +0900
	c = checker.NewCertificateFilesChecker(serverCertFile, "", "", "")
	certFileInfoList = c.Details().(checker.CertificateFilesDetails)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: all files contain one or more certificates")

	w.Reset()
	c.PrintDetails()

	assert.Equal(checker.OK, certFileInfoList[0].Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.pem", certFileInfoList[0].File)
	assert.Equal(checker.OK, certFileInfoList[0].CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfoList[0].CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfoList[0].CertificateInfoList[0].Subject)
	assert.Contains(w.String(), `    OK: Certificate File
        File: ../test/testdata/pki/cert/valid/server-a-rsa.pem
        Certificate:
            - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

	// Root certificates not found
	// Returns OK because the certificate path is not validated.
	//
	// OK: all files contain one or more certificates
	//     OK: Certificate File
	//         File: ../test/testdata/pki/cert/valid/server-a-rsa.pem
	//         Certificate:
	//             - OK: server-a.test
	//               Subject   : CN=server-a.test
	//               Issuer    : CN=Intermediate CA A RSA
	//               Expiration: 2022-06-21 12:16:35 +0900
	//     OK: Certificate Chain File
	//         File: ../test/testdata/pki/chain/chain-a-rsa.pem
	//         Certificate:
	//             - OK: Intermediate CA A RSA
	//               Subject   : CN=Intermediate CA A RSA
	//               Issuer    : CN=ROOT CA G2 RSA
	//               Expiration: 2031-06-22 12:16:35 +0900
	c = checker.NewCertificateFilesChecker(serverCertFile, chainCertFile, "", "")
	certFileInfoList = c.Details().(checker.CertificateFilesDetails)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: all files contain one or more certificates")

	w.Reset()
	c.PrintDetails()

	assert.Equal(checker.OK, certFileInfoList[0].Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.pem", certFileInfoList[0].File)
	assert.Equal(checker.OK, certFileInfoList[0].CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfoList[0].CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfoList[0].CertificateInfoList[0].Subject)
	assert.Contains(w.String(), `    OK: Certificate File
        File: ../test/testdata/pki/cert/valid/server-a-rsa.pem
        Certificate:
            - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

	assert.Equal(checker.OK, certFileInfoList[1].Status)
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", certFileInfoList[1].File)
	assert.Equal(checker.OK, certFileInfoList[1].CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfoList[1].CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfoList[1].CertificateInfoList[0].Subject)
	assert.Contains(w.String(), `    OK: Certificate Chain File
        File: ../test/testdata/pki/chain/chain-a-rsa.pem
        Certificate:
            - OK: Intermediate CA A RSA
              Subject   : CN=Intermediate CA A RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: `)

	// Server certificate is expired.
	//
	// CRITICAL: the certificate has expired on 2020-01-01 09:00:00 +0900
	//     ERROR: Certificate File
	//         File: ../test/testdata/pki/cert/expired/server-a-rsa.pem
	//         Error: the certificate has expired on 2020-01-01 09:00:00 +0900
	//         Certificate:
	//             - ERROR: server-a.test
	//               Subject   : CN=server-a.test
	//               Issuer    : CN=Intermediate CA A RSA
	//               Expiration: 2020-01-01 09:00:00 +0900
	//               Error     : the certificate has expired on 2020-01-01 09:00:00 +0900
	//     OK: Certificate Chain File
	//         File: ../test/testdata/pki/chain/chain-a-rsa.pem
	//         Certificate:
	//             - OK: Intermediate CA A RSA
	//               Subject   : CN=Intermediate CA A RSA
	//               Issuer    : CN=ROOT CA G2 RSA
	//               Expiration: 2031-06-23 13:42:19 +0900
	c = checker.NewCertificateFilesChecker(expiredServerCertFile, chainCertFile, "", "")
	certFileInfoList = c.Details().(checker.CertificateFilesDetails)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.CRITICAL, c.Status())
	assert.Contains(w.String(), "CRITICAL: the certificate has expired on")

	w.Reset()
	c.PrintDetails()

	assert.Equal(checker.ERROR, certFileInfoList[0].Status)
	assert.Equal("../test/testdata/pki/cert/expired/server-a-rsa.pem", certFileInfoList[0].File)
	assert.Equal(checker.ERROR, certFileInfoList[0].CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfoList[0].CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfoList[0].CertificateInfoList[0].Subject)
	assert.Contains(w.String(), `    ERROR: Certificate File
        File: ../test/testdata/pki/cert/expired/server-a-rsa.pem
        Error: the certificate has expired on `)
	assert.Contains(w.String(), `        Certificate:
            - ERROR: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)
	assert.Contains(w.String(), `              Error     : the certificate has expired on `)

	assert.Equal(checker.OK, certFileInfoList[1].Status)
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", certFileInfoList[1].File)
	assert.Equal(checker.OK, certFileInfoList[1].CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfoList[1].CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfoList[1].CertificateInfoList[0].Subject)
	assert.Contains(w.String(), `    OK: Certificate Chain File
        File: ../test/testdata/pki/chain/chain-a-rsa.pem
        Certificate:
            - OK: Intermediate CA A RSA
              Subject   : CN=Intermediate CA A RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: `)

	// OK
	//
	// OK: all files contain one or more certificates
	//     OK: Certificate File
	//         File: ../test/testdata/pki/cert/valid/server-a-rsa.pem
	//         Certificate:
	//             - OK: server-a.test
	//               Subject   : CN=server-a.test
	//               Issuer    : CN=Intermediate CA A RSA
	//               Expiration: 2022-06-21 12:16:35 +0900
	//     OK: Certificate Chain File
	//         File: ../test/testdata/pki/chain/chain-a-rsa.pem
	//         Certificate:
	//             - OK: Intermediate CA A RSA
	//               Subject   : CN=Intermediate CA A RSA
	//               Issuer    : CN=ROOT CA G2 RSA
	//               Expiration: 2031-06-22 12:16:35 +0900
	//     OK: Root Certificates File (list only, unverified)
	//         File: ../test/testdata/pki/root-ca/ca-root.pem
	//         Certificate:
	//             - INFO: ROOT CA G1 RSA
	//               Subject   : CN=ROOT CA G1 RSA
	//               Issuer    : CN=ROOT CA G1 RSA
	//               Expiration: 2035-01-01 09:00:00 +0900
	//             - INFO: ROOT CA G2 RSA
	//               Subject   : CN=ROOT CA G2 RSA
	//               Issuer    : CN=ROOT CA G2 RSA
	//               Expiration: 2035-01-01 09:00:00 +0900
	//             - INFO: ROOT CA G2 ECDSA
	//               Subject   : CN=ROOT CA G2 ECDSA
	//               Issuer    : CN=ROOT CA G2 ECDSA
	//               Expiration: 2035-01-01 09:00:00 +0900`)
	c = checker.NewCertificateFilesChecker(serverCertFile, chainCertFile, "", rootCertFile)
	certFileInfoList = c.Details().(checker.CertificateFilesDetails)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: all files contain one or more certificates")

	w.Reset()
	c.PrintDetails()

	assert.Equal(checker.OK, certFileInfoList[0].Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.pem", certFileInfoList[0].File)
	assert.Equal(checker.OK, certFileInfoList[0].CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfoList[0].CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfoList[0].CertificateInfoList[0].Subject)
	assert.Contains(w.String(), `    OK: Certificate File
        File: ../test/testdata/pki/cert/valid/server-a-rsa.pem
        Certificate:
            - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

	assert.Equal(checker.OK, certFileInfoList[1].Status)
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", certFileInfoList[1].File)
	assert.Equal(checker.OK, certFileInfoList[1].CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfoList[1].CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfoList[1].CertificateInfoList[0].Subject)
	assert.Contains(w.String(), `    OK: Certificate Chain File
        File: ../test/testdata/pki/chain/chain-a-rsa.pem
        Certificate:
            - OK: Intermediate CA A RSA
              Subject   : CN=Intermediate CA A RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: `)

	assert.Equal(checker.OK, certFileInfoList[2].Status)
	assert.Equal("../test/testdata/pki/root-ca/ca-root.pem", certFileInfoList[2].File)
	assert.Equal("ROOT CA G1 RSA", certFileInfoList[2].CertificateInfoList[0].CommonName)
	assert.Equal("ROOT CA G2 RSA", certFileInfoList[2].CertificateInfoList[1].CommonName)
	assert.Equal("ROOT CA G2 ECDSA", certFileInfoList[2].CertificateInfoList[2].CommonName)
	assert.Contains(w.String(), `    OK: Root Certificates File (list only, unverified)
        File: ../test/testdata/pki/root-ca/ca-root.pem
        Certificate:
            - INFO: ROOT CA G1 RSA
              Subject   : CN=ROOT CA G1 RSA
              Issuer    : CN=ROOT CA G1 RSA
              Expiration: `)

	// OK
	//
	// OK: all files contain one or more certificates
	//     OK: Certificate File
	//         File: ../test/testdata/pki/cert/valid/server-a-rsa.pem
	//         Certificate:
	//             - OK: server-a.test
	//               Subject   : CN=server-a.test
	//               Issuer    : CN=Intermediate CA A RSA
	//               Expiration: 2022-06-21 12:16:35 +0900
	//     OK: Certificate Chain File
	//         File: ../test/testdata/pki/chain/chain-a-rsa.pem
	//         Certificate:
	//             - OK: Intermediate CA A RSA
	//               Subject   : CN=Intermediate CA A RSA
	//               Issuer    : CN=ROOT CA G2 RSA
	//               Expiration: 2031-06-22 12:16:35 +0900
	//     OK: CA Certificate File
	//         File: ../test/testdata/pki/chain/ca.pem
	//         Certificate:
	//             - OK: Intermediate CA A RSA
	//               Subject   : CN=Intermediate CA A RSA
	//               Issuer    : CN=ROOT CA G2 RSA
	//               Expiration: 2031-06-22 12:16:35 +0900
	//             - OK: ROOT CA G2 RSA
	//               Subject   : CN=ROOT CA G2 RSA
	//               Issuer    : CN=ROOT CA G2 RSA
	//               Expiration: 2035-01-01 09:00:00 +0900
	//     OK: Root Certificates File (list only, unverified)
	//         File: ../test/testdata/pki/root-ca/ca-root.pem
	//         Certificate:
	//             - INFO: ROOT CA G1 RSA
	//               Subject   : CN=ROOT CA G1 RSA
	//               Issuer    : CN=ROOT CA G1 RSA
	//               Expiration: 2035-01-01 09:00:00 +0900
	//             - INFO: ROOT CA G2 RSA
	//               Subject   : CN=ROOT CA G2 RSA
	//               Issuer    : CN=ROOT CA G2 RSA
	//               Expiration: 2035-01-01 09:00:00 +0900
	//             - INFO: ROOT CA G2 ECDSA
	//               Subject   : CN=ROOT CA G2 ECDSA
	//               Issuer    : CN=ROOT CA G2 ECDSA
	//               Expiration: 2035-01-01 09:00:00 +0900`)
	c = checker.NewCertificateFilesChecker(serverCertFile, chainCertFile, caCertFile, rootCertFile)
	certFileInfoList = c.Details().(checker.CertificateFilesDetails)

	w.Reset()
	c.PrintStatus()
	assert.Equal(checker.OK, c.Status())
	assert.Contains(w.String(), "OK: all files contain one or more certificates")

	w.Reset()
	c.PrintDetails()

	assert.Equal(checker.OK, certFileInfoList[0].Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.pem", certFileInfoList[0].File)
	assert.Equal(checker.OK, certFileInfoList[0].CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfoList[0].CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfoList[0].CertificateInfoList[0].Subject)
	assert.Contains(w.String(), `    OK: Certificate File
        File: ../test/testdata/pki/cert/valid/server-a-rsa.pem
        Certificate:
            - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

	assert.Equal(checker.OK, certFileInfoList[1].Status)
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", certFileInfoList[1].File)
	assert.Equal(checker.OK, certFileInfoList[1].CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfoList[1].CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfoList[1].CertificateInfoList[0].Subject)
	assert.Contains(w.String(), `    OK: Certificate Chain File
        File: ../test/testdata/pki/chain/chain-a-rsa.pem
        Certificate:
            - OK: Intermediate CA A RSA
              Subject   : CN=Intermediate CA A RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: `)

	assert.Equal(checker.OK, certFileInfoList[2].Status)
	assert.Equal("../test/testdata/pki/chain/ca.pem", certFileInfoList[2].File)
	assert.Equal(checker.OK, certFileInfoList[2].CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfoList[2].CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfoList[2].CertificateInfoList[0].Subject)
	assert.Equal(checker.OK, certFileInfoList[2].CertificateInfoList[1].Status)
	assert.Equal("ROOT CA G2 RSA", certFileInfoList[2].CertificateInfoList[1].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", certFileInfoList[2].CertificateInfoList[1].Subject)
	assert.Contains(w.String(), `    OK: CA Certificate File
        File: ../test/testdata/pki/chain/ca.pem
        Certificate:
            - OK: Intermediate CA A RSA
              Subject   : CN=Intermediate CA A RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: `)
	assert.Contains(w.String(), `
            - OK: ROOT CA G2 RSA
              Subject   : CN=ROOT CA G2 RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: `)

	assert.Equal("../test/testdata/pki/root-ca/ca-root.pem", certFileInfoList[3].File)
	assert.Equal("ROOT CA G1 RSA", certFileInfoList[3].CertificateInfoList[0].CommonName)
	assert.Equal("ROOT CA G2 RSA", certFileInfoList[3].CertificateInfoList[1].CommonName)
	assert.Equal("ROOT CA G2 ECDSA", certFileInfoList[3].CertificateInfoList[2].CommonName)
	assert.Contains(w.String(), `    OK: Root Certificates File (list only, unverified)
        File: ../test/testdata/pki/root-ca/ca-root.pem
        Certificate:
            - INFO: ROOT CA G1 RSA
              Subject   : CN=ROOT CA G1 RSA
              Issuer    : CN=ROOT CA G1 RSA
              Expiration: `)
}

func TestCertificateFilesChecker(t *testing.T) {
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)
	checker.SetVerbose(2)
	checker.SetDNType(x509util.StrictDN)
	checker.SetCurrentTime(time.Now())

	serverCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.pem"
	chainCertFile := "../test/testdata/pki/chain/chain-a-rsa.pem"
	rootCertFile := "../test/testdata/pki/root-ca/ca-root.pem"

	c := checker.NewCertificateFilesChecker(serverCertFile, chainCertFile, "", rootCertFile)
	assert.Equal("Certificate Files", c.Name())
	assert.Equal(checker.OK, c.Status())
	assert.Equal("all files contain one or more certificates", c.Message())
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.pem", c.Details().(checker.CertificateFilesDetails)[0].File)

	c.PrintName()
	assert.Equal("[Certificate Files]\n", w.String())

	w.Reset()
	c.PrintStatus()
	assert.Equal("OK: all files contain one or more certificates\n", w.String())

	w.Reset()
	c.PrintDetails()
	assert.Contains(w.String(), `    OK: Certificate File
        File: ../test/testdata/pki/cert/valid/server-a-rsa.pem
        Certificate:
            - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)
}
