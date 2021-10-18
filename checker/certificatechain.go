// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CheckCertificateChain checks wheather the certificate chain is valid.
func CheckCertificateChain(serverCert *x509.Certificate, intermediateCerts []*x509.Certificate, rootCerts []*x509.Certificate) State {
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
	chains, err := getCertificateChains(serverCert, intermediateCerts, rootCerts)
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

		if parent.Subject.String() != parent.Issuer.String() {
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

func getCertificateChains(serverCert *x509.Certificate, intermediateCerts []*x509.Certificate, rootCerts []*x509.Certificate) (chains [][]*x509.Certificate, err error) {
	roots, err := x509util.GetRootCertPool(rootCerts)
	if err != nil {
		return nil, err
	}

	intermediates := x509util.GetIntermediateCertPool(intermediateCerts)

	opts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}

	chains, err = serverCert.Verify(opts)
	if err != nil {
		// When Verify() fails, the status of each certificate is unknown.
		// So, it builds a certificate chain.
		var chain []*x509.Certificate
		chain = append(chain, serverCert)
		chain = append(chain, intermediateCerts...)
		rootCert, err := getRootCertificate(intermediateCerts, rootCerts)
		if err != nil {
			return nil, err
		}
		if rootCert != nil {
			chain = append(chain, rootCert)
		}
		chains = append(chains, chain)
	}
	return chains, err
}

func getRootCertificate(intermediateCerts []*x509.Certificate, rootCerts []*x509.Certificate) (rootCert *x509.Certificate, err error) {
	roots, err := x509util.GetRootCertPool(rootCerts)
	if err != nil {
		return nil, err
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	for _, intermediateCert := range intermediateCerts {
		chains, _ := intermediateCert.Verify(opts)
		for _, chain := range chains {
			for _, cert := range chain {
				if err := intermediateCert.CheckSignatureFrom(cert); err == nil {
					rootCert = cert
					break
				}
			}
		}
	}
	return rootCert, nil
}
