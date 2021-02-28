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
		printDetailsLine("Issuer : %s", x509util.DistinguishedName(cert.Issuer, dnType))
		printDetailsLine("Subject: %s", x509util.DistinguishedName(cert.Subject, dnType))
		if len(cert.DNSNames) > 0 {
			printDetailsLine("Subject Alternative Names:")
			for _, dnsName := range cert.DNSNames {
				printDetailsLine("    DNS: %s", dnsName)
			}
		}
		printDetailsLine("Validity:")
		printDetailsLine("    Not Before: %s", cert.NotBefore)
		printDetailsLine("    Not After : %s", cert.NotAfter)

		if verbose > 1 {
			publicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(cert)
			printDetailsLine("Subject Public Key Info:")
			printDetailsLine("    Public Key Algorithm: %s", publicKeyInfo.PublicKeyAlgorithm.String())
			printDetailsLine("        %s", publicKeyInfo.TypeLabel)
			publicKeyTypeName := "pub"
			if publicKeyInfo.PublicKeyAlgorithm == x509.RSA {
				publicKeyTypeName = "Modulus"
			}
			printDetailsLine("        %s:", publicKeyTypeName)

			const length = 45
			var line string
			for i := 0; i < len(publicKeyInfo.KeyString); i = i + length {
				if i+length < len(publicKeyInfo.KeyString) {
					line = publicKeyInfo.KeyString[i : i+length]
				} else {
					line = publicKeyInfo.KeyString[i:]
				}
				printDetailsLine("             %s", line)
			}

			for key, value := range publicKeyInfo.Option {
				printDetailsLine("        %s: %s", key, value)
			}
		}
	}

	state := State{
		Name:         name,
		Status:       OK,
		Message:      "the certificate information is as follows",
		Data:         cert,
		PrintDetails: printDetails,
	}

	return state
}
