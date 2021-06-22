// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CheckCertificateList checks peer certificates.
func CheckCertificateList(certs []*x509.Certificate) State {
	const name = "Peer Certificate List"

	n := len(certs)
	certInfoList := make([]CertificateInfo, n)

	printDetails := func(verbose int, dnType x509util.DNType) {
		for _, certInfo := range certInfoList {
			printDetailsLine("- %s: %s", certInfo.Status.ColorString(), certInfo.CommonName)
			printDetailsLine("    Subject   : %v", x509util.DistinguishedName(certInfo.Certificate.Subject, dnType))
			printDetailsLine("    Issuer    : %v", x509util.DistinguishedName(certInfo.Certificate.Issuer, dnType))
			printDetailsLine("    Expiration: %v", certInfo.Certificate.NotAfter.Local().Format(timeFormat))
			if certInfo.Message != "" {
				if certInfo.Status == ERROR {
					printDetailsLine("    Error     : %s", certInfo.Message)
				} else {
					printDetailsLine("    Message   : %s", certInfo.Message)
				}
			}
		}
	}

	var parent *x509.Certificate
	for i := 0; i < n; i++ {
		cert := certs[n-i-1]
		certInfo := getCertificateInfo(cert, parent, false)
		certInfoList[n-i-1] = certInfo
		parent = cert
	}

	status := OK
	message := "certificates are valid"
	var messages []string

	for _, certInfo := range certInfoList {
		if certInfo.Status == ERROR {
			status = CRITICAL
			messages = append(messages, certInfo.Message)
		}
	}

	if len(messages) > 0 {
		message = strings.Join(messages, " / ")
	}

	if len(certInfoList) == 0 {
		status = CRITICAL
		message = "no certificate"
	}

	state := State{
		Name:         name,
		Status:       status,
		Message:      message,
		Data:         certInfoList,
		PrintDetails: printDetails,
	}
	return state
}
