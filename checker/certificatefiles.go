// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CertificateFileInfo describes an information in a certificate file.
type CertificateFileInfo struct {
	Label               string
	Name                string
	Status              Status
	Message             string
	CertificateInfoList []CertificateInfo
	isRoot              bool
}

// CheckCertificateFiles checks files.
func CheckCertificateFiles(certFile string, chainFile string, caFile string, rootFile string) State {
	const name = "Certificate Files"

	var certFileInfoList []CertificateFileInfo

	printDetails := func(verbose int, dnType x509util.DNType) {
		for _, certFileInfo := range certFileInfoList {
			printDetailsLine("%s: %s", certFileInfo.Status.ColorString(), certFileInfo.Label)
			printDetailsLine("    File: %s", certFileInfo.Name)
			if certFileInfo.Message != "" {
				if certFileInfo.Status == ERROR {
					printDetailsLine("    Error: %s", certFileInfo.Message)
				} else {
					printDetailsLine("    Message: %s", certFileInfo.Message)
				}
			}
			if len(certFileInfo.CertificateInfoList) == 0 {
				continue
			}

			printDetailsLine("    Certificate:")
			if !certFileInfo.isRoot {
				for _, certInfo := range certFileInfo.CertificateInfoList {
					printDetailsLine("        - %s: %s", certInfo.Status.ColorString(), certInfo.CommonName)
					printDetailsLine("          Subject   : %s", x509util.DistinguishedName(certInfo.Certificate.Subject, dnType))
					printDetailsLine("          Issuer    : %s", x509util.DistinguishedName(certInfo.Certificate.Issuer, dnType))
					printDetailsLine("          Expiration: %v", certInfo.Certificate.NotAfter.Local().Format(timeFormat))
					if certInfo.Message != "" {
						if certInfo.Status == ERROR {
							printDetailsLine("          Error     : %s", certInfo.Message)
						} else {
							printDetailsLine("          Message   : %s", certInfo.Message)
						}
					}
				}
			} else {
				// Root Certificates File (list only, unverified)
				const maxCert = 3
				for i, certInfo := range certFileInfo.CertificateInfoList {
					printDetailsLine("        - %s", certInfo.CommonName)
					if i >= maxCert {
						printDetailsLine("        - ...(omitted)")
						break
					}
				}
			}
		}
	}

	var (
		certFileInfo      CertificateFileInfo
		chainCertFileInfo CertificateFileInfo
		parent            *x509.Certificate
	)

	if chainFile != "" {
		chainCertFileInfo, parent = getCertificateFileInfo("Certificate Chain File", chainFile, nil, false)
	}

	if certFile != "" {
		certFileInfo, _ = getCertificateFileInfo("Certificate File", certFile, parent, false)
		certFileInfoList = append(certFileInfoList, certFileInfo)
	}

	if chainFile != "" {
		certFileInfoList = append(certFileInfoList, chainCertFileInfo)
	}

	if caFile != "" {
		certFileInfo, _ = getCertificateFileInfo("CA Certificate File", caFile, nil, false)
		certFileInfoList = append(certFileInfoList, certFileInfo)
	}

	if rootFile != "" {
		certFileInfo, _ = getCertificateFileInfo("Root Certificates File (list only, unverified)", rootFile, nil, true)
		certFileInfoList = append(certFileInfoList, certFileInfo)
	}

	status := OK
	message := "all files contain one or more certificates"
	var messages []string

	for _, certFileInfo := range certFileInfoList {
		if certFileInfo.Status == ERROR {
			status = CRITICAL
			messages = append(messages, certFileInfo.Message)
		}
	}

	if len(messages) > 0 {
		message = strings.Join(messages, " / ")
	}

	state := State{
		Name:         name,
		Status:       status,
		Message:      message,
		Data:         certFileInfoList,
		PrintDetails: printDetails,
	}
	return state
}

func getCertificateFileInfo(label string, certFile string, parent *x509.Certificate, isRoot bool) (CertificateFileInfo, *x509.Certificate) {
	status := OK
	var message string
	var certInfoList []CertificateInfo

	certs, err := x509util.ParseCertificateFiles(certFile)
	if err != nil {
		status = ERROR
		message = err.Error()
	} else if isRoot {
		for _, cert := range certs {
			certInfo := CertificateInfo{
				CommonName:  cert.Subject.CommonName,
				Certificate: cert,
			}
			certInfoList = append(certInfoList, certInfo)
		}
	} else {
		n := len(certs)
		certInfoList = make([]CertificateInfo, n, n)
		for i := 0; i < n; i++ {
			cert := certs[n-i-1]
			certInfo := getCertificateInfo(cert, parent, false)
			if certInfo.Status == ERROR {
				status = ERROR
			}
			certInfoList[n-i-1] = certInfo
			parent = cert
		}
	}

	certFileInfo := CertificateFileInfo{
		Label:               label,
		Name:                certFile,
		Status:              status,
		Message:             message,
		CertificateInfoList: certInfoList,
		isRoot:              isRoot,
	}

	return certFileInfo, parent
}
