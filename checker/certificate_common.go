// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CertificateInfo describes a status of a certificate.
type CertificateInfo struct {
	CommonName  string
	Certificate *x509.Certificate
	Status      Status
	Message     string
}

func getCertificateInfo(cert *x509.Certificate, parent *x509.Certificate, forceParentToCheck bool) CertificateInfo {
	status := OK
	var message string

	err := x509util.VerifyCertificate(cert, parent, forceParentToCheck)
	if err != nil {
		status = ERROR
		message = err.Error()
	}

	certInfo := CertificateInfo{
		CommonName:  cert.Subject.CommonName,
		Certificate: cert,
		Status:      status,
		Message:     message,
	}
	return certInfo
}

func printCertificate(cert *x509.Certificate, verbose int, dnType x509util.DNType, indent int) {
	printDetailsLine(indent, "Issuer : %s", x509util.DistinguishedName(cert.Issuer, dnType))
	printDetailsLine(indent, "Subject: %s", x509util.DistinguishedName(cert.Subject, dnType))
	if len(cert.DNSNames) > 0 {
		printDetailsLine(indent, "Subject Alternative Names:")
		for _, dnsName := range cert.DNSNames {
			printDetailsLine(indent, "    DNS: %s", dnsName)
		}
	}
	printDetailsLine(indent, "Validity:")
	printDetailsLine(indent, "    Not Before: %s", cert.NotBefore)
	printDetailsLine(indent, "    Not After : %s", cert.NotAfter)

	if verbose > 1 {
		publicKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(cert)
		publicKeyInfo.SourceName = "Subject Public Key Info"
		// Decrease verbosity.
		printPublicKey(publicKeyInfo, verbose-1, indent)
	}
}

func printPublicKey(publicKeyInfo x509util.PublicKeyInfo, verbose int, indent int) {
	printDetailsLine(indent, "%s:", publicKeyInfo.SourceName)
	printDetailsLine(indent, "    Public Key Algorithm: %s", publicKeyInfo.PublicKeyAlgorithm.String())

	printDetailsLine(indent, "        %s", publicKeyInfo.TypeLabel)

	publicKeyTypeName := "pub"
	if publicKeyInfo.PublicKeyAlgorithm == x509.RSA {
		publicKeyTypeName = "Modulus"
	}
	printDetailsLine(indent, "        %s:", publicKeyTypeName)

	if verbose < 2 {
		printDetailsLine(indent, "            %s", publicKeyInfo.KeyString[:45])
		printDetailsLine(indent, "            ...(omitted)")
	} else if verbose >= 2 {
		const length = 45
		var line string
		for i := 0; i < len(publicKeyInfo.KeyString); i = i + length {
			if i+length < len(publicKeyInfo.KeyString) {
				line = publicKeyInfo.KeyString[i : i+length]

			} else {
				line = publicKeyInfo.KeyString[i:]
			}
			printDetailsLine(indent, "            %s", line)
		}
	}

	for key, value := range publicKeyInfo.Option {
		printDetailsLine(indent, "        %s: %s", key, value)
	}
}
