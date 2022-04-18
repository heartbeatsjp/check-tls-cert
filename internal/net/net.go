// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package net

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/net/imaputil"
	"github.com/heartbeatsjp/check-tls-cert/net/pop3util"
	"github.com/heartbeatsjp/check-tls-cert/net/smtputil"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/mattn/go-colorable"
)

type OCSPOption int

const (
	// Disable OCSP checker.
	OCSPNo OCSPOption = iota

	// Check the response from OCSP Stapling. If there is no OCSP response, the status will be "INFO".
	OCSPAsIs

	// Check the response from OCSP Stapling. If there is no OCSP response, retry the TLS connection up to two times every second. If there is still no OCSP response, the status will be "WARNING".
	OCSPStapling

	// Check the response from OCSP Responder.
	OCSPResponder

	// Check the response from OCSP Stapling. If there is no OCSP response, check the response from OCSP Responder.
	OCSPFallback
)

type NetCommandOptions struct {
	Hostname         string
	Network          string
	IpAddress        string
	Port             uint16
	TLSMinVersion    uint16
	StartTLS         string
	OCSPOption       OCSPOption
	Timeout          int
	Warning          int
	Critical         int
	RootFile         string
	EnableSSLCertDir bool
	OutputFormat     checker.OutputFormat
}

// Run checks certificates.
func Run(opts NetCommandOptions) (int, error) {
	var (
		rootCerts    []*x509.Certificate
		rootCertPool *x509.CertPool
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

	tlsConfig := tls.Config{
		RootCAs:                rootCertPool,
		ServerName:             opts.Hostname,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		MinVersion:             opts.TLSMinVersion,
	}

	addr := fmt.Sprintf("%s:%d", opts.Hostname, opts.Port)
	if opts.IpAddress != "" {
		addr = fmt.Sprintf("%s:%d", opts.IpAddress, opts.Port)
	}

	connectionStateInfo, err := getConnectionStateInfo(opts.Network, addr, opts.StartTLS, &tlsConfig, opts.Timeout)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	var checkerList []checker.Checker
	checkerList = append(checkerList, checker.NewCertificateChecker(connectionStateInfo.ServerCertificate()))
	checkerList = append(checkerList, checker.NewCertificateListChecker(connectionStateInfo.Certificates))
	checkerList = append(checkerList, checker.NewHostnameChecker(opts.Hostname, connectionStateInfo.ServerCertificate()))
	checkerList = append(checkerList, checker.NewValidityChecker(connectionStateInfo.ServerCertificate(), opts.Warning, opts.Critical))
	checkerList = append(checkerList, checker.NewCertificateChainChecker(connectionStateInfo.Certificates, rootCertPool))

	switch opts.OCSPOption {
	case OCSPAsIs:
		checkerList = append(checkerList, checker.NewOCSPStaplingChecker(connectionStateInfo.OCSPResponse, connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool, true))
	case OCSPStapling:
		ocspResponse := connectionStateInfo.OCSPResponse
		for i := 0; i < 2; i++ {
			if len(ocspResponse) > 0 {
				break
			}
			time.Sleep(time.Second)
			connectionStateInfo, err := getConnectionStateInfo(opts.Network, addr, opts.StartTLS, &tlsConfig, opts.Timeout)
			if err != nil {
				return checker.UNKNOWN.Code(), err
			}
			ocspResponse = connectionStateInfo.OCSPResponse
		}
		checkerList = append(checkerList, checker.NewOCSPStaplingChecker(connectionStateInfo.OCSPResponse, connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool, false))
	case OCSPResponder:
		checkerList = append(checkerList, checker.NewOCSPResponderChecker(connectionStateInfo.ServerCertificate(), connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool))
	case OCSPFallback:
		if len(connectionStateInfo.OCSPResponse) > 0 {
			checkerList = append(checkerList, checker.NewOCSPStaplingChecker(connectionStateInfo.OCSPResponse, connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool, true))
		} else {
			checkerList = append(checkerList, checker.NewOCSPResponderChecker(connectionStateInfo.ServerCertificate(), connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool))
		}
	default:
	}

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

type ConnectionStateInfo struct {
	Certificates []*x509.Certificate
	OCSPResponse []byte
}

func (i ConnectionStateInfo) ServerCertificate() *x509.Certificate {
	var serverCert *x509.Certificate
	if len(i.Certificates) > 0 {
		serverCert = i.Certificates[0]
	}
	return serverCert
}

func (i ConnectionStateInfo) IssuerCertificate() *x509.Certificate {
	var issuerCert *x509.Certificate
	if len(i.Certificates) > 1 {
		issuerCert = i.Certificates[1]
	}
	return issuerCert
}

func (i ConnectionStateInfo) IntermediateCertificates() []*x509.Certificate {
	var intermediateCert []*x509.Certificate
	if len(i.Certificates) > 1 {
		intermediateCert = i.Certificates[1:]
	}
	return intermediateCert
}

func getConnectionStateInfo(network string, addr string, startTLS string, tlsConfig *tls.Config, timeout int) (*ConnectionStateInfo, error) {
	var connectionState tls.ConnectionState
	switch startTLS {
	case "":
		dialer := net.Dialer{Timeout: time.Second * time.Duration(timeout)}
		conn, err := tls.DialWithDialer(&dialer, network, addr, tlsConfig)
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		connectionState = conn.ConnectionState()
	case "smtp":
		client, err := smtputil.Dial(network, addr, time.Second*time.Duration(timeout))
		if err != nil {
			return nil, err
		}
		defer client.Quit()
		err = client.StartTLS(tlsConfig)
		if err != nil {
			return nil, err
		}
		connectionState, _ = client.TLSConnectionState()
	case "pop3":
		client, err := pop3util.Dial(network, addr, time.Second*time.Duration(timeout))
		if err != nil {
			return nil, err
		}
		defer client.Quit()
		err = client.StartTLS(tlsConfig)
		if err != nil {
			return nil, err
		}
		connectionState, _ = client.TLSConnectionState()
	case "imap":
		client, err := imaputil.Dial(network, addr, time.Second*time.Duration(timeout))
		if err != nil {
			return nil, err
		}
		defer client.Logout()
		err = client.StartTLS(tlsConfig)
		if err != nil {
			return nil, err
		}
		connectionState, _ = client.TLSConnectionState()
	default:
		return nil, errors.New("an unsupported protocol was specified with the --starttls option")
	}

	connectionStateInfo := ConnectionStateInfo{
		Certificates: connectionState.PeerCertificates,
		OCSPResponse: connectionState.OCSPResponse,
	}

	return &connectionStateInfo, nil
}
