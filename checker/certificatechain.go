// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"bytes"
	"crypto/x509"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CertificateChainChecker represents wheather certificate chains are valid.
type CertificateChainChecker struct {
	name    string
	status  Status
	message string
	details CertificateChainDetails
}

func NewCertificateChainChecker(certs []*x509.Certificate, rootCertPool *x509.CertPool) *CertificateChainChecker {
	const name = "Certificate Chains"

	var (
		certInfoChains [][]CertificateInfo
		certChains     [][]*x509.Certificate
		err            error
	)

	status := OK
	message := "the certificate chain is valid"

	serverCert := certs[0]
	var intermediateCerts []*x509.Certificate
	if len(certs) > 1 {
		intermediateCerts = certs[1:]
	}

	opts := x509.VerifyOptions{
		Intermediates: x509util.GetIntermediateCertPool(intermediateCerts),
		Roots:         rootCertPool,
		CurrentTime:   currentTime,
	}

	certChains, err = serverCert.Verify(opts)
	if err != nil {
		// When Verify() fails, the status of each certificate is unknown.
		// So, it builds a certificate chain.
		certChains = x509util.BuildCertificateChains(certs, rootCertPool, currentTime)
		status = CRITICAL
	}

	for _, chain := range certChains {
		var certInfoChain []CertificateInfo
		n := len(chain)
		if n == 0 {
			continue
		}

		root := chain[n-1]
		if !bytes.Equal(root.RawIssuer, root.RawSubject) {
			// If the first certificate is not a root CA, add the root CA information.
			certInfo := CertificateInfo{
				CommonName: root.Issuer.CommonName,
				Status:     INFO,
				Message:    "a valid root certificate cannot be found, or the certificate chain is broken",
			}
			certInfoChain = append(certInfoChain, certInfo)
		}

		var parent *x509.Certificate
		for i := 0; i < n; i++ {
			cert := chain[n-i-1]
			certInfo := NewCertificateInfo(cert, parent, true)
			certInfoChain = append(certInfoChain, certInfo)
			parent = cert
		}
		certInfoChains = append(certInfoChains, certInfoChain)
	}

	for _, certInfoChain := range certInfoChains {
		for _, certInfo := range certInfoChain {
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

	details := NewCertificateChainDetails(certInfoChains)

	return &CertificateChainChecker{
		name:    name,
		status:  status,
		message: message,
		details: details,
	}
}

func (c *CertificateChainChecker) Name() string {
	return c.name
}

func (c *CertificateChainChecker) Status() Status {
	return c.status
}

func (c *CertificateChainChecker) Message() string {
	return c.message
}

func (c *CertificateChainChecker) Details() interface{} {
	return c.details
}

func (c *CertificateChainChecker) PrintName() {
	printCheckerName(c)
}

func (c *CertificateChainChecker) PrintStatus() {
	printCheckerStatus(c)
}

func (c *CertificateChainChecker) PrintDetails() {
	for _, chain := range c.details {
		indent := 4
		for _, certInfo := range chain {
			printIndentedLine(indent, "- %s: %s", certInfo.Status.ColorString(), certInfo.CommonName)
			printKeyValueIfExists(indent+4, "Subject   ", certInfo.Subject)
			printKeyValueIfExists(indent+4, "Issuer    ", certInfo.Issuer)
			printKeyValueIfExists(indent+4, "Expiration", certInfo.Expiration)
			printKeyValueIfExists(indent+4, "Message   ", certInfo.Message)
			printKeyValueIfExists(indent+4, "Error     ", certInfo.Error)
			indent = indent + 2
		}
	}
}

type CertificateChainDetails [][]CertificateInfo

func NewCertificateChainDetails(c [][]CertificateInfo) CertificateChainDetails {
	return c
}
