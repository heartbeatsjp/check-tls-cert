// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"crypto/x509"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/x509util"
)

type CertificateInfo struct {
	CommonName   string `json:"commonName"`
	Status       Status `json:"-"`
	StatusString string `json:"status"`
	Subject      string `json:"subject"`
	Issuer       string `json:"issuer"`
	Expiration   string `json:"expiration"`
	Message      string `json:"message,omitempty"`
	Error        string `json:"error,omitempty"`
}

func NewCertificateInfo(cert *x509.Certificate, parent *x509.Certificate, forceParentToCheck bool) CertificateInfo {
	status := OK
	var msg, errmsg string

	err := x509util.VerifyCertificate(cert, parent, currentTime, forceParentToCheck)
	if err != nil {
		status = ERROR
		errmsg = err.Error()
	}

	return CertificateInfo{
		CommonName:   cert.Subject.CommonName,
		Status:       status,
		StatusString: status.String(),
		Subject:      x509util.DistinguishedName(cert.Subject, dnType),
		Issuer:       x509util.DistinguishedName(cert.Issuer, dnType),
		Expiration:   cert.NotAfter.Local().Format(timeFormat),
		Message:      msg,
		Error:        errmsg,
	}
}

type CertificateDetails struct {
	Issuer               string           `json:"issuer"`
	Subject              string           `json:"subject"`
	SubjectAltName       []subjectAltName `json:"subjectAltName,omitempty"`
	Validity             validity         `json:"validity"`
	SubjectPublicKeyInfo *publicKeyInfo   `json:"subjectPublicKeyInfo,omitempty"`
}

type subjectAltName struct {
	DNS       string `json:"dns,omitempty"`
	IPAddress string `json:"iPAddress,omitempty"`
	Email     string `json:"email,omitempty"`
	URI       string `json:"uri,omitempty"`
}

type validity struct {
	NotBefore string `json:"notBefore"`
	NotAfter  string `json:"notAfter"`
}

type publicKeyInfo struct {
	Name               string   `json:"-"`
	PublicKeyAlgorithm string   `json:"publicKeyAlgorithm,omitempty"`
	Type               string   `json:"type,omitempty"`
	KeyStringLines     []string `json:"-"`
	Modulus            string   `json:"modulus,omitempty"`
	Exponent           string   `json:"exponent,omitempty"`
	Pub                string   `json:"pub,omitempty"`
	NISTCurve          string   `json:"nISTCurve,omitempty"`
}

func NewCertificateDetails(cert *x509.Certificate) *CertificateDetails {
	var sans []subjectAltName
	var subjPubKeyInfo *publicKeyInfo

	sans = getSubjectAltNames(cert)

	if verbose > 1 {
		var omit bool
		if verbose == 2 {
			omit = true
		}
		pubKeyInfo, _ := x509util.ExtractPublicKeyFromCertificate(cert)
		subjPubKeyInfo = getPublicKeyInfo(pubKeyInfo, omit)
	}

	return &CertificateDetails{
		Issuer:         x509util.DistinguishedName(cert.Issuer, dnType),
		Subject:        x509util.DistinguishedName(cert.Subject, dnType),
		SubjectAltName: sans,
		Validity: validity{
			NotBefore: cert.NotBefore.String(),
			NotAfter:  cert.NotAfter.String(),
		},
		SubjectPublicKeyInfo: subjPubKeyInfo,
	}
}

func getSubjectAltNames(cert *x509.Certificate) []subjectAltName {
	var sans []subjectAltName

	for _, dNSName := range cert.DNSNames {
		sans = append(sans, subjectAltName{DNS: dNSName})
	}
	for _, iPAddress := range cert.IPAddresses {
		sans = append(sans, subjectAltName{IPAddress: iPAddress.String()})
	}
	for _, rfc822Name := range cert.EmailAddresses {
		sans = append(sans, subjectAltName{Email: rfc822Name})
	}
	for _, uri := range cert.URIs {
		sans = append(sans, subjectAltName{URI: uri.String()})
	}
	return sans
}

func getPublicKeyInfo(pubKeyInfo x509util.PublicKeyInfo, omit bool) *publicKeyInfo {
	var (
		modulus   string
		exponent  string
		pub       string
		nISTCurve string
	)

	keyStringLines := createPublicKeyStringLines(pubKeyInfo.KeyString, omit)
	keyString := strings.Join(keyStringLines, "\n")

	switch pubKeyInfo.PublicKeyAlgorithm {
	case x509.RSA:
		modulus = keyString
		exponent = pubKeyInfo.Option["Exponent"]
	case x509.ECDSA:
		pub = keyString
		nISTCurve = pubKeyInfo.Option["NIST CURVE"]
	case x509.Ed25519:
		pub = keyString
	}

	return &publicKeyInfo{
		Name:               pubKeyInfo.SourceName,
		PublicKeyAlgorithm: pubKeyInfo.PublicKeyAlgorithm.String(),
		Type:               pubKeyInfo.Type,
		KeyStringLines:     keyStringLines,
		Modulus:            modulus,
		Exponent:           exponent,
		Pub:                pub,
		NISTCurve:          nISTCurve,
	}
}

func createPublicKeyStringLines(keyString string, omit bool) []string {
	const lineLength = 45
	var lines []string
	if omit {
		lines = append(lines, keyString[:lineLength])
		lines = append(lines, "...(omitted)")
	} else {
		var line string
		for i := 0; i < len(keyString); i = i + lineLength {
			if i+lineLength < len(keyString) {
				line = keyString[i : i+lineLength]
			} else {
				line = keyString[i:]
			}
			lines = append(lines, line)
		}
	}
	return lines
}

func printCertificate(indent int, details *CertificateDetails) {
	printKeyValueIfExists(indent, "Issuer ", details.Issuer)
	printKeyValueIfExists(indent, "Subject", details.Subject)
	printSubjectAltName(indent, details.SubjectAltName)
	printKey(indent, "Validity")
	printKeyValueIfExists(indent+4, "Not Before", details.Validity.NotBefore)
	printKeyValueIfExists(indent+4, "Not After ", details.Validity.NotAfter)

	if verbose > 1 {
		printKey(indent, "Subject Public Key Info")
		printPublicKey(indent, details.SubjectPublicKeyInfo)
	}
}

func printSubjectAltName(indent int, sans []subjectAltName) {
	if len(sans) == 0 {
		return
	}

	printKey(indent, "Subject Alternative Name")
	for _, item := range sans {
		printKeyValueIfExists(indent+4, "DNS", item.DNS)
		printKeyValueIfExists(indent+4, "IP Address", item.IPAddress)
		printKeyValueIfExists(indent+4, "email", item.Email)
		printKeyValueIfExists(indent+4, "URI", item.URI)
	}
}

func printPublicKey(indent int, pubKeyInfo *publicKeyInfo) {
	printKeyValueIfExists(indent+4, "Public Key Algorithm", pubKeyInfo.PublicKeyAlgorithm)
	printIndentedLine(indent+8, pubKeyInfo.Type)
	printKeyIfExists(indent+8, "Modulus", pubKeyInfo.Modulus)
	printKeyIfExists(indent+8, "pub", pubKeyInfo.Pub)

	for _, line := range pubKeyInfo.KeyStringLines {
		printIndentedLine(indent+12, line)
	}

	printKeyValueIfExists(indent+8, "Exponent", pubKeyInfo.Exponent)
	printKeyValueIfExists(indent+8, "NIST Curve", pubKeyInfo.NISTCurve)
}
