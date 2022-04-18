// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

// CertificateFilesChecker represents certificate files are.
type CertificateFilesChecker struct {
	name    string
	status  Status
	message string
	details CertificateFilesDetails
}

func NewCertificateFilesChecker(certFile string, chainFile string, caFile string, rootFile string) *CertificateFilesChecker {
	const name = "Certificate Files"

	var certFileInfoList []CertificateFileInfo

	var (
		certFileInfo      CertificateFileInfo
		chainCertFileInfo CertificateFileInfo
		parent            *x509.Certificate
	)

	if chainFile != "" {
		chainCertFileInfo, parent = NewCertificateFileInfo("Certificate Chain File", chainFile, nil, false)
	}

	if certFile != "" {
		certFileInfo, _ = NewCertificateFileInfo("Certificate File", certFile, parent, false)
		certFileInfoList = append(certFileInfoList, certFileInfo)
	}

	if chainFile != "" {
		certFileInfoList = append(certFileInfoList, chainCertFileInfo)
	}

	if caFile != "" {
		certFileInfo, _ = NewCertificateFileInfo("CA Certificate File", caFile, nil, false)
		certFileInfoList = append(certFileInfoList, certFileInfo)
	}

	if rootFile != "" {
		certFileInfo, _ = NewCertificateFileInfo("Root Certificates File (list only, unverified)", rootFile, nil, true)
		certFileInfoList = append(certFileInfoList, certFileInfo)
	}

	status := OK
	message := "all files contain one or more certificates"
	var errmsgs []string

	for _, certFileInfo := range certFileInfoList {
		if certFileInfo.Status == ERROR {
			status = CRITICAL
			errmsgs = append(errmsgs, certFileInfo.Error)
		}
	}

	if len(errmsgs) > 0 {
		message = strings.Join(errmsgs, " / ")
	}

	details := NewCertificateFilesDetails(certFileInfoList)

	return &CertificateFilesChecker{
		name:    name,
		status:  status,
		message: message,
		details: details,
	}
}

func (c *CertificateFilesChecker) Name() string {
	return c.name
}

func (c *CertificateFilesChecker) Status() Status {
	return c.status
}
func (c *CertificateFilesChecker) Message() string {
	return c.message
}

func (c *CertificateFilesChecker) Details() interface{} {
	return c.details
}

func (c *CertificateFilesChecker) PrintName() {
	printCheckerName(c)
}

func (c *CertificateFilesChecker) PrintStatus() {
	printCheckerStatus(c)
}

func (c *CertificateFilesChecker) PrintDetails() {
	for _, certFileInfo := range c.details {
		printIndentedLine(4, "%s: %s", certFileInfo.Status.ColorString(), certFileInfo.Name)

		printKeyValueIfExists(8, "File", certFileInfo.File)
		printKeyValueIfExists(8, "Error", certFileInfo.Error)
		if len(certFileInfo.CertificateInfoList) == 0 {
			continue
		}

		printIndentedLine(8, "Certificate:")
		if !certFileInfo.isRoot {
			for _, certInfo := range certFileInfo.CertificateInfoList {
				printIndentedLine(12, "- %s: %s", certInfo.Status.ColorString(), certInfo.CommonName)
				printKeyValueIfExists(14, "Subject   ", certInfo.Subject)
				printKeyValueIfExists(14, "Issuer    ", certInfo.Issuer)
				printKeyValueIfExists(14, "Expiration", certInfo.Expiration)
				printKeyValueIfExists(14, "Message   ", certInfo.Message)
				printKeyValueIfExists(14, "Error     ", certInfo.Error)
			}
		} else {
			// Root Certificates File (list only, unverified)
			const maxCert = 3
			for i, certInfo := range certFileInfo.CertificateInfoList {
				printIndentedLine(12, "- %s: %s", certInfo.Status.ColorString(), certInfo.CommonName)
				printKeyValueIfExists(14, "Subject   ", certInfo.Subject)
				printKeyValueIfExists(14, "Issuer    ", certInfo.Issuer)
				printKeyValueIfExists(14, "Expiration", certInfo.Expiration)
				if i >= maxCert {
					printIndentedLine(12, "- ...(omitted)")
					break
				}
			}
		}
	}
}

// CertificateFileInfo describes an information in a certificate file.
type CertificateFileInfo struct {
	Name                string            `json:"name"`
	File                string            `json:"file"`
	Status              Status            `json:"-"`
	StatusString        string            `json:"status"`
	Error               string            `json:"error,omitempty"`
	CertificateInfoList []CertificateInfo `json:"certificate"`
	isRoot              bool              `json:"-"`
}

func NewCertificateFileInfo(name string, certFile string, parent *x509.Certificate, isRoot bool) (CertificateFileInfo, *x509.Certificate) {
	status := OK
	var errmsg string
	var certInfoList []CertificateInfo

	certs, err := x509util.ParseCertificateFiles(certFile)
	if err != nil {
		status = ERROR
		errmsg = err.Error()
	} else if isRoot {
		for _, cert := range certs {
			certInfo := CertificateInfo{
				CommonName:   cert.Subject.CommonName,
				Status:       INFO,
				StatusString: INFO.String(),
				Subject:      x509util.DistinguishedName(cert.Subject, dnType),
				Issuer:       x509util.DistinguishedName(cert.Issuer, dnType),
				Expiration:   cert.NotAfter.Local().Format(timeFormat),
			}
			certInfoList = append(certInfoList, certInfo)
		}
	} else {
		var errmsgs []string
		n := len(certs)
		certInfoList = make([]CertificateInfo, n)
		for i := 0; i < n; i++ {
			cert := certs[n-i-1]
			certInfo := NewCertificateInfo(cert, parent, false)
			if certInfo.Status == ERROR {
				status = ERROR
				errmsgs = append(errmsgs, certInfo.Error)
			}
			certInfoList[n-i-1] = certInfo
			parent = cert
		}
		if len(errmsgs) > 0 {
			errmsg = strings.Join(errmsgs, " / ")
		}
	}

	certFileInfo := CertificateFileInfo{
		Name:                name,
		File:                certFile,
		Status:              status,
		StatusString:        status.String(),
		Error:               errmsg,
		CertificateInfoList: certInfoList,
		isRoot:              isRoot,
	}

	return certFileInfo, parent
}

type CertificateFilesDetails []CertificateFileInfo

func NewCertificateFilesDetails(list []CertificateFileInfo) CertificateFilesDetails {
	return list
}
