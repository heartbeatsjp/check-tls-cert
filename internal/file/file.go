// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import (
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// Run checks certificates.
func Run(hostname string, keyFile string, certFile string, chainFile string, rootFile string, caFile string, warning int, critical int, dnType x509util.DNType, verbose int) (int, error) {
	var err error

	privateKeyInfo, err := x509util.ParsePrivateKeyFile(keyFile)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	publicKeyInfoInPrivateKey, err := x509util.ExtractPublicKeyFromPrivateKey(privateKeyInfo)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	certs, err := x509util.ParseCertificateFiles(certFile, chainFile)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}
	serverCert := certs[0]
	intermediateCerts := certs[1:]

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

	var rootCerts []*x509.Certificate
	if rootFile != "" {
		rootCerts, err = x509util.ParseCertificateFiles(rootFile)
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
	stateList = append(stateList, checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts))
	stateList.Print(verbose, dnType)
	return stateList.Code(), err
}
