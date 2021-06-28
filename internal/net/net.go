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
)

// Run checks certificates.
func Run(hostname string, ipAddress string, port uint16, network string, startTLS string, timeout int, rootFile string, warning int, critical int, dnType x509util.DNType, verbose int) (int, error) {
	var (
		rootCerts         []*x509.Certificate
		intermediateCerts []*x509.Certificate
		issuerCert        *x509.Certificate
		roots             *x509.CertPool
		err               error
	)

	if rootFile != "" {
		rootCerts, err = x509util.ParseCertificateFiles(rootFile)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
		roots = x509.NewCertPool()
		for _, cert := range rootCerts {
			roots.AddCert(cert)
		}
	} else {
		roots, err = x509.SystemCertPool()
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
	}

	addr := fmt.Sprintf("%s:%d", hostname, port)
	if ipAddress != "" {
		addr = fmt.Sprintf("%s:%d", ipAddress, port)
	}

	tlsConfig := tls.Config{
		RootCAs:            roots,
		ServerName:         hostname,
		InsecureSkipVerify: true,
	}

	var connectionState tls.ConnectionState
	switch startTLS {
	case "":
		dialer := net.Dialer{Timeout: time.Second * time.Duration(timeout)}
		conn, err := tls.DialWithDialer(&dialer, network, addr, &tlsConfig)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
		defer conn.Close()
		connectionState = conn.ConnectionState()
	case "smtp":
		client, err := smtputil.Dial(network, addr, time.Second*time.Duration(timeout))
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
		defer client.Quit()
		err = client.StartTLS(&tlsConfig)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
		connectionState, _ = client.TLSConnectionState()
	case "pop3":
		client, err := pop3util.Dial(network, addr, time.Second*time.Duration(timeout))
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
		defer client.Quit()
		err = client.StartTLS(&tlsConfig)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
		connectionState, _ = client.TLSConnectionState()
	case "imap":
		client, err := imaputil.Dial(network, addr, time.Second*time.Duration(timeout))
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
		defer client.Logout()
		err = client.StartTLS(&tlsConfig)
		if err != nil {
			return checker.UNKNOWN.Code(), err
		}
		connectionState, _ = client.TLSConnectionState()
	default:
		return checker.UNKNOWN.Code(), errors.New("an unsupported protocol was specified with the --starttls option")
	}

	certs := connectionState.PeerCertificates

	serverCert := certs[0]
	if len(certs) >= 2 {
		intermediateCerts = certs[1:]
		issuerCert = certs[1]
	} else {
		intermediateCerts = []*x509.Certificate{}
	}

	var stateList checker.StateList
	stateList = append(stateList, checker.CheckCertificate(serverCert))
	stateList = append(stateList, checker.CheckCertificateList(certs))
	stateList = append(stateList, checker.CheckHostname(hostname, serverCert))
	stateList = append(stateList, checker.CheckValidity(serverCert, warning, critical))
	stateList = append(stateList, checker.CheckCertificateChain(serverCert, intermediateCerts, rootCerts))
	stateList = append(stateList, checker.CheckOCSPStapling(issuerCert, connectionState.OCSPResponse))
	stateList.Print(verbose, dnType)
	return stateList.Code(), err
}
