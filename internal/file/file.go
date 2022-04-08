// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import (
	"crypto/x509"
	"errors"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/mattn/go-colorable"
)

// Run checks certificates.
func Run(hostname string, keyFile string, certFile string, chainFile string, rootFile string, caFile string, passwordFile string, warning int, critical int, enableSSLCertDir bool, dnType x509util.DNType, verbose int) (int, error) {
	var (
		rootCerts    []*x509.Certificate
		rootCertPool *x509.CertPool
		password     []byte
		err          error
	)

	checker.SetOutput(colorable.NewColorableStdout())

	if rootFile != "" {
		rootCerts, err = x509util.ParseCertificateFiles(rootFile)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
	}

	rootCertPool, err = x509util.GetRootCertPool(rootCerts, enableSSLCertDir)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	certs, err := x509util.ParseCertificateFiles(certFile, chainFile)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	var serverCert *x509.Certificate
	if len(certs) == 0 {
		return checker.UNKNOWN.Code(), errors.New("no valid certificates")
	}
	serverCert = certs[0]

	if len(passwordFile) > 0 {
		password, err = x509util.ReadPasswordFile(passwordFile)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
	}

	privateKeyInfo, err := x509util.ParsePrivateKeyFile(keyFile, password)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	publicKeyInfoInPrivateKey, err := x509util.ExtractPublicKeyFromPrivateKey(privateKeyInfo)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	publicKeyInfo, err := x509util.ExtractPublicKeyFromCertificate(serverCert)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	if caFile != "" {
		_, err = x509util.ParseCertificateFiles(caFile)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
	}

	var stateList checker.StateList
	stateList = append(stateList, checker.CheckCertificate(serverCert))
	stateList = append(stateList, checker.CheckCertificateFiles(certFile, chainFile, caFile, rootFile))
	stateList = append(stateList, checker.CheckKeyPair(publicKeyInfoInPrivateKey, publicKeyInfo))
	stateList = append(stateList, checker.CheckHostname(hostname, serverCert))
	stateList = append(stateList, checker.CheckValidity(serverCert, warning, critical))
	stateList = append(stateList, checker.CheckCertificateChain(certs, rootCertPool))
	stateList.Print(verbose, dnType)
	return stateList.Code(), err
}
