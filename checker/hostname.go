// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"fmt"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CheckHostname checks whether the hostname is valid for the certificate.
func CheckHostname(hostname string, cert *x509.Certificate) State {
	const name = "Hostname"

	printDetails := func(verbose int, dnType x509util.DNType) {
		printDetailsLine("Common Name: %s", cert.Subject.CommonName)
		if len(cert.DNSNames) > 0 {
			printDetailsLine("Subject Alternative Names:")
			for _, dnsName := range cert.DNSNames {
				printDetailsLine("    DNS: %s", dnsName)
			}
		}
	}

	var (
		status  Status
		message string
	)

	err := cert.VerifyHostname(hostname)
	if err != nil {
		status = CRITICAL
		message = fmt.Sprintf("the hostname '%s' is invalid for the certificate / %s", hostname, err.Error())
	} else {
		status = OK
		message = fmt.Sprintf("the hostname '%s' is valid for the certificate", hostname)
	}

	state := State{
		Name:         name,
		Status:       status,
		Message:      message,
		Data:         cert,
		PrintDetails: printDetails,
	}
	return state
}
