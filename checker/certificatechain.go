// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"bytes"
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CheckCertificateChain checks wheather the certificate chain is valid.
func CheckCertificateChain(certs []*x509.Certificate, rootCertPool *x509.CertPool) State {
	const name = "Certificate Chains"

	var certInfoInChains [][]CertificateInfo

	printDetails := func(verbose int, dnType x509util.DNType) {
		for _, certInfoInChain := range certInfoInChains {
			indent := 4

			for _, certInfo := range certInfoInChain {
				printDetailsLine(indent, "- %s: %s", certInfo.Status.ColorString(), certInfo.CommonName)
				if certInfo.Certificate != nil {
					printDetailsLine(indent, "    Subject   : %v", x509util.DistinguishedName(certInfo.Certificate.Subject, dnType))
					printDetailsLine(indent, "    Issuer    : %v", x509util.DistinguishedName(certInfo.Certificate.Issuer, dnType))
					printDetailsLine(indent, "    Expiration: %v", certInfo.Certificate.NotAfter.Local().Format(timeFormat))
				}
				if certInfo.Message != "" {
					if certInfo.Status == ERROR {
						printDetailsLine(indent, "    Error     : %v", certInfo.Message)
					} else {
						printDetailsLine(indent, "    Message   : %s", certInfo.Message)
					}
				}

				indent = indent + 2
			}
		}
	}

	status := OK
	message := "the certificate chain is valid"
	chains, err := getCertificateChains(certs, rootCertPool)
	if err != nil {
		status = CRITICAL
	}

	for _, chain := range chains {
		var certInfoInChain []CertificateInfo
		n := len(chain)
		if n == 0 {
			continue
		}
		parent := chain[n-1]

		if !bytes.Equal(parent.RawIssuer, parent.RawSubject) {
			// If the first certificate is not the root CA, add the information of the root CA.
			certInfo := CertificateInfo{
				CommonName: parent.Issuer.CommonName,
				Status:     INFO,
				Message:    "a valid root certificate cannot be found, or the certificate chain is broken",
			}
			certInfoInChain = append(certInfoInChain, certInfo)
			parent = nil
		}

		for i := 0; i < n; i++ {
			cert := chain[n-i-1]
			certInfo := getCertificateInfo(cert, parent, true)
			certInfoInChain = append(certInfoInChain, certInfo)
			parent = cert
		}
		certInfoInChains = append(certInfoInChains, certInfoInChain)
	}

	for _, certInfoInChain := range certInfoInChains {
		for _, certInfo := range certInfoInChain {
			if certInfo.Status == ERROR {
				status = CRITICAL
			}
		}
	}

	if status == CRITICAL {
		message = "the certificate chain is invalid"
		if err != nil {
			message += " / " + err.Error()
		}
	}

	state := State{
		Name:         name,
		Status:       status,
		Message:      message,
		Data:         certInfoInChains,
		PrintDetails: printDetails,
	}
	return state
}

func getCertificateChains(certs []*x509.Certificate, rootCertPool *x509.CertPool) (chains [][]*x509.Certificate, err error) {
	serverCert := certs[0]
	var intermediateCerts []*x509.Certificate
	if len(certs) > 1 {
		intermediateCerts = certs[1:]
	}

	opts := x509.VerifyOptions{
		Intermediates: x509util.GetIntermediateCertPool(intermediateCerts),
		Roots:         rootCertPool,
	}

	chains, err = serverCert.Verify(opts)
	if err != nil {
		// When Verify() fails, the status of each certificate is unknown.
		// So, it builds a certificate chain.
		chains = x509util.BuildCertificateChains(certs, rootCertPool)
	}
	return chains, err
}
