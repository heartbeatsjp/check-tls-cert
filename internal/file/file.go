// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package file

import (
	"crypto/x509"
	"errors"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/mattn/go-colorable"
)

type FileCommandOptions struct {
	Hostname         string
	KeyFile          string
	CertFile         string
	ChainFile        string
	CAFile           string
	PasswordFile     string
	Warning          int
	Critical         int
	RootFile         string
	EnableSSLCertDir bool
	OutputFormat     checker.OutputFormat
}

// Run checks certificates.
func Run(opts FileCommandOptions) (int, error) {
	var (
		rootCerts    []*x509.Certificate
		rootCertPool *x509.CertPool
		password     []byte
		err          error
	)

	checker.SetOutput(colorable.NewColorableStdout())

	if opts.RootFile != "" {
		rootCerts, err = x509util.ParseCertificateFiles(opts.RootFile)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
	}

	rootCertPool, err = x509util.GetRootCertPool(rootCerts, opts.EnableSSLCertDir)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	certs, err := x509util.ParseCertificateFiles(opts.CertFile, opts.ChainFile)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	if len(certs) == 0 {
		return checker.UNKNOWN.Code(), errors.New("no valid certificates")
	}
	serverCert := certs[0]

	if len(opts.PasswordFile) > 0 {
		password, err = x509util.ReadPasswordFile(opts.PasswordFile)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
	}

	privKeyInfo, err := x509util.ParsePrivateKeyFile(opts.KeyFile, password)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	pubKeyInfoInPrivKey, err := x509util.ExtractPublicKeyFromPrivateKey(privKeyInfo)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	pubKeyInfo, err := x509util.ExtractPublicKeyFromCertificate(serverCert)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	if opts.CAFile != "" {
		_, err = x509util.ParseCertificateFiles(opts.CAFile)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
	}

	var checkerList []checker.Checker
	checkerList = append(checkerList, checker.NewCertificateChecker(serverCert))
	checkerList = append(checkerList, checker.NewCertificateFilesChecker(opts.CertFile, opts.ChainFile, opts.CAFile, opts.RootFile))
	checkerList = append(checkerList, checker.NewKeyPairChecker(pubKeyInfoInPrivKey, pubKeyInfo))
	checkerList = append(checkerList, checker.NewHostnameChecker(opts.Hostname, serverCert))
	checkerList = append(checkerList, checker.NewValidityChecker(serverCert, opts.Warning, opts.Critical))
	checkerList = append(checkerList, checker.NewCertificateChainChecker(certs, rootCertPool))

	summary := checker.NewSummary(checkerList)
	result := checker.NewResult(summary, checkerList)
	switch opts.OutputFormat {
	case checker.JSONFormat:
		result.PrintJSON()
	default:
		result.Print()
	}
	return summary.Status().Code(), nil
}
