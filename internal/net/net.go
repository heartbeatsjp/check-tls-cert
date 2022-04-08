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

// Run checks certificates.
func Run(hostname string, ipAddress string, port uint16, network string, tlsMinVersion uint16, startTLS string, ocspOption OCSPOption, timeout int, rootFile string, warning int, critical int, enableSSLCertDir bool, dnType x509util.DNType, verbose int) (int, error) {
	var (
		rootCerts    []*x509.Certificate
		rootCertPool *x509.CertPool
		err          error
	)

	checker.SetOutput(colorable.NewColorableStdout())

	if rootFile != "" {
		rootCerts, err = x509util.ParseCertificateFiles(rootFile)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
	}

	rootCertPool, err = x509util.GetRootCertPool(rootCerts, enableSSLCertDir)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	tlsConfig := tls.Config{
		RootCAs:                rootCertPool,
		ServerName:             hostname,
		InsecureSkipVerify:     true,
		SessionTicketsDisabled: true,
		MinVersion:             tlsMinVersion,
	}

	addr := fmt.Sprintf("%s:%d", hostname, port)
	if ipAddress != "" {
		addr = fmt.Sprintf("%s:%d", ipAddress, port)
	}

	connectionStateInfo, err := getConnectionStateInfo(network, addr, startTLS, &tlsConfig, timeout)
	if err != nil {
		return checker.UNKNOWN.Code(), err
	}

	var stateList checker.StateList
	stateList = append(stateList, checker.CheckCertificate(connectionStateInfo.ServerCertificate()))
	stateList = append(stateList, checker.CheckCertificateList(connectionStateInfo.Certificates))
	stateList = append(stateList, checker.CheckHostname(hostname, connectionStateInfo.ServerCertificate()))
	stateList = append(stateList, checker.CheckValidity(connectionStateInfo.ServerCertificate(), warning, critical))
	stateList = append(stateList, checker.CheckCertificateChain(connectionStateInfo.Certificates, rootCertPool))

	switch ocspOption {
	case OCSPAsIs:
		stateList = append(stateList, checker.CheckOCSPStapling(connectionStateInfo.OCSPResponse, connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool, true))
	case OCSPStapling:
		ocspResponse := connectionStateInfo.OCSPResponse
		for i := 0; i < 2; i++ {
			if len(ocspResponse) > 0 {
				break
			}
			time.Sleep(time.Second)
			connectionStateInfo, err := getConnectionStateInfo(network, addr, startTLS, &tlsConfig, timeout)
			if err != nil {
				return checker.UNKNOWN.Code(), err
			}
			ocspResponse = connectionStateInfo.OCSPResponse
		}
		stateList = append(stateList, checker.CheckOCSPStapling(connectionStateInfo.OCSPResponse, connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool, false))
	case OCSPResponder:
		stateList = append(stateList, checker.CheckOCSPResponder(connectionStateInfo.ServerCertificate(), connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool))
	case OCSPFallback:
		if len(connectionStateInfo.OCSPResponse) > 0 {
			stateList = append(stateList, checker.CheckOCSPStapling(connectionStateInfo.OCSPResponse, connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool, true))
		} else {
			stateList = append(stateList, checker.CheckOCSPResponder(connectionStateInfo.ServerCertificate(), connectionStateInfo.IssuerCertificate(), connectionStateInfo.IntermediateCertificates(), rootCertPool))
		}
	default:
	}

	stateList.Print(verbose, dnType)
	return stateList.Code(), err
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
