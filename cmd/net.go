// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	netcmd "github.com/heartbeatsjp/check-tls-cert/internal/net"
	"github.com/spf13/cobra"
)

var (
	ipAddress     net.IP
	ipAddressStr  string
	port          uint16
	useIPv4       bool
	useIPv6       bool
	tlsMinVerStr  string
	tlsMinVersion uint16
	startTLS      string
	ocspOptionStr string
	ocspOption    netcmd.OCSPOption
	timeout       int
	netCmdOpts    netcmd.NetCommandOptions

	netCmd = &cobra.Command{
		Use:   "net",
		Short: "Connects to a host and checks the TLS certificate.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			if ipAddress != nil {
				ipAddressStr = ipAddress.String()
			}

			network := "tcp"
			if useIPv6 {
				network = "tcp6"
			} else if useIPv4 {
				network = "tcp4"
			}

			if tlsMinVersion, err = parseTLSMinVersion(tlsMinVerStr); err != nil {
				return err
			}

			if ocspOption, err = parseOCSPOption(ocspOptionStr); err != nil {
				return err
			}

			netCmdOpts = netcmd.NetCommandOptions{
				Hostname:         hostname,
				Network:          network,
				IpAddress:        ipAddressStr,
				Port:             port,
				TLSMinVersion:    tlsMinVersion,
				StartTLS:         startTLS,
				OCSPOption:       ocspOption,
				Timeout:          timeout,
				Warning:          warning,
				Critical:         critical,
				RootFile:         rootFile,
				EnableSSLCertDir: enableSSLCertDir,
				OutputFormat:     outputFormat,
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := netcmd.Run(netCmdOpts)
			if err != nil {
				switch outputFormat {
				case checker.JSONFormat:
					r := checker.NewResult(checker.NewErrorSummary(err), nil)
					r.PrintJSON()
					os.Exit(0)
				default:
					fmt.Printf("Error: %s\n", err.Error())
					os.Exit(checker.UNKNOWN.Code())
				}
				return err
			}
			switch outputFormat {
			case checker.JSONFormat:
				os.Exit(0)
			default:
				os.Exit(code)
			}
			return nil
		},
	}
)

func init() {
	netCmd.Flags().StringVarP(&hostname, "hostname", "H", "", "`hostname` for verifying certificate")
	netCmd.MarkFlagRequired("hostname")
	netCmd.Flags().IPVarP(&ipAddress, "ip-address", "I", nil, "IP `address`")
	netCmd.Flags().Uint16VarP(&port, "port", "p", 443, "port `number`")
	netCmd.Flags().BoolVarP(&useIPv4, "use-ipv4", "4", false, "use IPv4")
	netCmd.Flags().BoolVarP(&useIPv6, "use-ipv6", "6", false, "use IPv6")
	netCmd.Flags().StringVar(&startTLS, "starttls", "", "STARTTLS `type`. 'smtp', 'pop3, or 'imap'")
	netCmd.Flags().StringVar(&tlsMinVerStr, "tls-min-version", "1.0", "TLS minimum `version`. '1.0', '1.1', '1.2', or '1.3'")
	netCmd.Flags().StringVar(&ocspOptionStr, "ocsp", "as-is", "OCSP checker `type`. 'no', 'as-is', 'stapling', 'responder', or 'fallback'. 'responder' and 'fallback' are experimental.")
	netCmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "connection timeout in `seconds`")
	netCmd.Flags().IntVarP(&warning, "warning", "w", 28, "warning threshold in `days` before expiration date")
	netCmd.Flags().IntVarP(&critical, "critical", "c", 14, "critical threshold in `days` before expiration date")
	netCmd.Flags().SortFlags = false

	rootCmd.AddCommand(netCmd)
}

func parseTLSMinVersion(str string) (tlsMinVersion uint16, err error) {
	switch str {
	case "1.0":
		tlsMinVersion = tls.VersionTLS10
	case "1.1":
		tlsMinVersion = tls.VersionTLS11
	case "1.2":
		tlsMinVersion = tls.VersionTLS12
	case "1.3":
		tlsMinVersion = tls.VersionTLS13
	default:
		err = errors.New("unknown TLS version in '--tls-min-version' option")
	}
	return tlsMinVersion, err
}

func parseOCSPOption(option string) (netcmd.OCSPOption, error) {
	var o netcmd.OCSPOption
	switch strings.ToLower(option) {
	case "no":
		o = netcmd.OCSPNo
	case "as-is":
		o = netcmd.OCSPAsIs
	case "stapling":
		o = netcmd.OCSPStapling
	case "responder":
		o = netcmd.OCSPResponder
	case "fallback":
		o = netcmd.OCSPFallback
	default:
		return 0, errors.New("unknown OCSP option type in '--ocsp' option")
	}
	return o, nil
}
