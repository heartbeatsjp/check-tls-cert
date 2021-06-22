// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker_test

import (
	"strings"
	"testing"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/stretchr/testify/assert"
)

func TestCheckCertificateFiles(t *testing.T) {
	var (
		state        checker.State
		certFileInfo checker.CertificateFileInfo
	)
	assert := assert.New(t)
	w := strings.Builder{}
	checker.SetOutput(&w)

	nonExistentFile := "../test/testdata/pki/misc/non-existent.crt"
	emptyFile := "../test/testdata/pki/misc/empty.crt"
	expiredServerCertFile := "../test/testdata/pki/cert/expired/server-a-rsa.crt"
	serverCertFile := "../test/testdata/pki/cert/valid/server-a-rsa.crt"
	chainCertFile := "../test/testdata/pki/chain/chain-a-rsa.pem"
	caCertFile := "../test/testdata/pki/chain/ca.pem"
	rootCertFile := "../test/testdata/pki/root-ca/ca-root.pem"

	// Non-existent file
	//
	// CRITICAL: open ../test/testdata/pki/misc/non-existent.crt: no such file or directory
	//     ERROR: Certificate File
	//         File: ../test/testdata/pki/misc/non-existent.crt
	//         Error: open ../test/testdata/pki/misc/non-existent.crt: no such file or directory
	state = checker.CheckCertificateFiles(nonExistentFile, "", "", "")

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: open ../test/testdata/pki/misc/non-existent.crt: no such file or directory")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Contains(w.String(), `    ERROR: Certificate File
        File: ../test/testdata/pki/misc/non-existent.crt
        Error: open ../test/testdata/pki/misc/non-existent.crt: no such file or directory`)

	// Empty file
	//
	// CRITICAL: no valid certificates
	//     ERROR: Certificate File
	//         File: ../test/testdata/pki/misc/empty.crt
	//         Error: no valid certificates
	state = checker.CheckCertificateFiles(emptyFile, "", "", "")

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: no valid certificates")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	assert.Contains(w.String(), `    ERROR: Certificate File
        File: ../test/testdata/pki/misc/empty.crt
        Error: no valid certificates`)

	// Intermediate and root certificates not found
	// Returns OK because the certificate path is not validated.
	//
	// OK: all files contain one or more certificates
	//     OK: Certificate File
	//         File: ../test/testdata/pki/cert/valid/server-a-rsa.crt
	//         Certificate:
	//             - OK: server-a.test
	//               Subject   : CN=server-a.test
	//               Issuer    : CN=Intermediate CA A RSA
	//               Expiration: 2022-06-21 12:16:35 +0900
	state = checker.CheckCertificateFiles(serverCertFile, "", "", "")

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: all files contain one or more certificates")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	certFileInfo = state.Data.([]checker.CertificateFileInfo)[0]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.crt", certFileInfo.Name)
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
	assert.Contains(w.String(), `    OK: Certificate File
        File: ../test/testdata/pki/cert/valid/server-a-rsa.crt
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
	//         File: ../test/testdata/pki/cert/valid/server-a-rsa.crt
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
	state = checker.CheckCertificateFiles(serverCertFile, chainCertFile, "", "")

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: all files contain one or more certificates")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	certFileInfo = state.Data.([]checker.CertificateFileInfo)[0]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.crt", certFileInfo.Name)
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
	assert.Contains(w.String(), `    OK: Certificate File
        File: ../test/testdata/pki/cert/valid/server-a-rsa.crt
        Certificate:
            - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

	certFileInfo = state.Data.([]checker.CertificateFileInfo)[1]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", certFileInfo.Name)
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
	assert.Contains(w.String(), `    OK: Certificate Chain File
        File: ../test/testdata/pki/chain/chain-a-rsa.pem
        Certificate:
            - OK: Intermediate CA A RSA
              Subject   : CN=Intermediate CA A RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: `)

	// Server certificate is expired.
	//
	// CRITICAL:
	//     ERROR: Certificate File
	//         File: ../test/testdata/pki/cert/expired/server-a-rsa.crt
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
	state = checker.CheckCertificateFiles(expiredServerCertFile, chainCertFile, "", "")

	w.Reset()
	state.Print()
	assert.Equal(checker.CRITICAL, state.Status)
	assert.Contains(w.String(), "CRITICAL: ")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	certFileInfo = state.Data.([]checker.CertificateFileInfo)[0]
	assert.Equal(checker.ERROR, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/cert/expired/server-a-rsa.crt", certFileInfo.Name)
	assert.Equal(checker.ERROR, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
	assert.Contains(w.String(), `    ERROR: Certificate File
        File: ../test/testdata/pki/cert/expired/server-a-rsa.crt
        Certificate:
            - ERROR: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

	certFileInfo = state.Data.([]checker.CertificateFileInfo)[1]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", certFileInfo.Name)
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
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
	//         File: ../test/testdata/pki/cert/valid/server-a-rsa.crt
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
	//             - ROOT CA G1 RSA
	//             - ROOT CA G2 RSA
	//             - ROOT CA G2 ECDSA
	state = checker.CheckCertificateFiles(serverCertFile, chainCertFile, "", rootCertFile)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: all files contain one or more certificates")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)
	certFileInfo = state.Data.([]checker.CertificateFileInfo)[0]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.crt", certFileInfo.Name)
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
	assert.Contains(w.String(), `    OK: Certificate File
        File: ../test/testdata/pki/cert/valid/server-a-rsa.crt
        Certificate:
            - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

	certFileInfo = state.Data.([]checker.CertificateFileInfo)[1]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", certFileInfo.Name)
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
	assert.Contains(w.String(), `    OK: Certificate Chain File
        File: ../test/testdata/pki/chain/chain-a-rsa.pem
        Certificate:
            - OK: Intermediate CA A RSA
              Subject   : CN=Intermediate CA A RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: `)

	certFileInfo = state.Data.([]checker.CertificateFileInfo)[2]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/root-ca/ca-root.pem", certFileInfo.Name)
	assert.Equal("ROOT CA G1 RSA", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("ROOT CA G2 RSA", certFileInfo.CertificateInfoList[1].CommonName)
	assert.Equal("ROOT CA G2 ECDSA", certFileInfo.CertificateInfoList[2].CommonName)
	assert.Contains(w.String(), `    OK: Root Certificates File (list only, unverified)
        File: ../test/testdata/pki/root-ca/ca-root.pem
        Certificate:
            - ROOT CA G1 RSA
            - ROOT CA G2 RSA
            - ROOT CA G2 ECDSA`)

	// OK
	//
	// OK: all files contain one or more certificates
	//     OK: Certificate File
	//         File: ../test/testdata/pki/cert/valid/server-a-rsa.crt
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
	//             - ROOT CA G1 RSA
	//             - ROOT CA G2 RSA
	//             - ROOT CA G2 ECDSA
	state = checker.CheckCertificateFiles(serverCertFile, chainCertFile, caCertFile, rootCertFile)

	w.Reset()
	state.Print()
	assert.Equal(checker.OK, state.Status)
	assert.Contains(w.String(), "OK: all files contain one or more certificates")

	w.Reset()
	state.PrintDetails(2, x509util.StrictDN)

	certFileInfo = state.Data.([]checker.CertificateFileInfo)[0]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/cert/valid/server-a-rsa.crt", certFileInfo.Name)
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("server-a.test", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=server-a.test", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
	assert.Contains(w.String(), `    OK: Certificate File
        File: ../test/testdata/pki/cert/valid/server-a-rsa.crt
        Certificate:
            - OK: server-a.test
              Subject   : CN=server-a.test
              Issuer    : CN=Intermediate CA A RSA
              Expiration: `)

	certFileInfo = state.Data.([]checker.CertificateFileInfo)[1]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/chain/chain-a-rsa.pem", certFileInfo.Name)
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
	assert.Contains(w.String(), `    OK: Certificate Chain File
        File: ../test/testdata/pki/chain/chain-a-rsa.pem
        Certificate:
            - OK: Intermediate CA A RSA
              Subject   : CN=Intermediate CA A RSA
              Issuer    : CN=ROOT CA G2 RSA
              Expiration: `)

	certFileInfo = state.Data.([]checker.CertificateFileInfo)[2]
	assert.Equal(checker.OK, certFileInfo.Status)
	assert.Equal("../test/testdata/pki/chain/ca.pem", certFileInfo.Name)
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[0].Status)
	assert.Equal("Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("CN=Intermediate CA A RSA", certFileInfo.CertificateInfoList[0].Certificate.Subject.String())
	assert.Equal(checker.OK, certFileInfo.CertificateInfoList[1].Status)
	assert.Equal("ROOT CA G2 RSA", certFileInfo.CertificateInfoList[1].CommonName)
	assert.Equal("CN=ROOT CA G2 RSA", certFileInfo.CertificateInfoList[1].Certificate.Subject.String())
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

	certFileInfo = state.Data.([]checker.CertificateFileInfo)[3]
	assert.Equal("../test/testdata/pki/root-ca/ca-root.pem", certFileInfo.Name)
	assert.Equal("ROOT CA G1 RSA", certFileInfo.CertificateInfoList[0].CommonName)
	assert.Equal("ROOT CA G2 RSA", certFileInfo.CertificateInfoList[1].CommonName)
	assert.Equal("ROOT CA G2 ECDSA", certFileInfo.CertificateInfoList[2].CommonName)
	assert.Contains(w.String(), `    OK: Root Certificates File (list only, unverified)
        File: ../test/testdata/pki/root-ca/ca-root.pem
        Certificate:
            - ROOT CA G1 RSA
            - ROOT CA G2 RSA
            - ROOT CA G2 ECDSA`)

}
