// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	net "github.com/heartbeatsjp/check-tls-cert/internal/net"
	"github.com/spf13/cobra"
)

var (
	ipAddress  string
	port       uint16
	useIPv4    bool
	useIPv6    bool
	startTLS   string
	ocspOption string
	timeout    int

	netCmd = &cobra.Command{
		Use:   "net",
		Short: "Connects to a host and checks the TLS certificate.",
		RunE: func(cmd *cobra.Command, args []string) error {
			network := "tcp"
			if useIPv6 {
				network = "tcp6"
			} else if useIPv4 {
				network = "tcp4"
			}

			dntype, err := parseDNType(dnType)
			if err != nil {
				fmt.Printf("ERROR: %s\n", err.Error())
				os.Exit(checker.UNKNOWN.Code())
			}

			ocspoption, err := parseOCSPOption(ocspOption)
			if err != nil {
				fmt.Printf("ERROR: %s\n", err.Error())
				os.Exit(checker.UNKNOWN.Code())
			}

			code, err := net.Run(hostname, ipAddress, port, network, startTLS, ocspoption, timeout, rootFile, warning, critical, dntype, verbose)
			if err != nil {
				fmt.Printf("ERROR: %s\n", err.Error())
			}
			os.Exit(code)
			return nil
		},
	}
)

func init() {
	netCmd.Flags().StringVarP(&hostname, "hostname", "H", "", "`hostname` for verifying certificate")
	netCmd.MarkFlagRequired("hostname")
	netCmd.Flags().StringVarP(&ipAddress, "ip-address", "I", "", "IP `address`")
	netCmd.Flags().Uint16VarP(&port, "port", "p", 443, "port `number`")
	netCmd.Flags().BoolVarP(&useIPv4, "use-ipv4", "4", false, "use IPv4")
	netCmd.Flags().BoolVarP(&useIPv6, "use-ipv6", "6", false, "use IPv6")
	netCmd.Flags().StringVar(&startTLS, "starttls", "", "STARTTLS `type`. 'smtp', 'pop3, or 'imap'")
	netCmd.Flags().StringVar(&ocspOption, "ocsp", "as-is", "OCSP checker `type`. 'as-is', 'stapling', 'responder', or 'fallback'. 'responder' and 'fallback' are experimental.")
	netCmd.Flags().IntVarP(&timeout, "timeout", "t", 10, "connection timeout in `seconds`")

	rootCmd.AddCommand(netCmd)
}

func parseOCSPOption(option string) (net.OCSPOption, error) {
	var o net.OCSPOption
	switch strings.ToLower(option) {
	case "as-is":
		o = net.OCSPAsIs
	case "stapling":
		o = net.OCSPStapling
	case "responder":
		o = net.OCSPResponder
	case "fallback":
		o = net.OCSPFallback
	default:
		return 0, errors.New("unknown checker type in '--ocsp' option")
	}
	return o, nil
}
