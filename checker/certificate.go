// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CheckCertificate prints a certificate information.
func CheckCertificate(cert *x509.Certificate) State {
	const name = "Certificate"

	printDetails := func(verbose int, dnType x509util.DNType) {
		printCertificate(cert, verbose, dnType, 4)
	}

	state := State{
		Name:         name,
		Status:       INFO,
		Message:      "the certificate information is as follows",
		Data:         cert,
		PrintDetails: printDetails,
	}

	return state
}
