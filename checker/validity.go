// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

const timeFormat = "2006-01-02 15:04:05 -0700"

// CheckValidity checks the validity of a certificate.
func CheckValidity(cert *x509.Certificate, warning int, critical int) State {
	const name = "Validity"

	printDetails := func(verbose int, dnType x509util.DNType) {
		printDetailsLine("Not Before: %s", cert.NotBefore.Local().Format(timeFormat))
		printDetailsLine("Not After : %s", cert.NotAfter.Local().Format(timeFormat))
	}

	var (
		status  Status
		message string
		err     error
	)

	//lint:ignore SA4006 It was detected by mistake.
	if message, err = x509util.VerifyValidity(cert, critical); err != nil {
		status = CRITICAL
		message = err.Error()
	} else if message, err = x509util.VerifyValidity(cert, warning); err != nil {
		status = WARNING
		message = err.Error()
	} else {
		status = OK
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
