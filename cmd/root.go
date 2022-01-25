// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/heartbeatsjp/check-tls-cert/version"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/spf13/cobra"
)

var (
	hostname         string
	warning          int
	critical         int
	rootFile         string
	enableSSLCertDir bool
	dnType           string
	verbose          int

	rootCmd = &cobra.Command{
		Use:     "check-tls-cert",
		Short:   "check-tls-cert is a TLS certificate checker",
		Version: version.Version,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Help()
			return nil
		},
	}
)

// Execute the `check-tls-cert` command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().IntVarP(&warning, "warning", "w", 28, "warning threshold in `days` before expiration date")
	rootCmd.PersistentFlags().IntVarP(&critical, "critical", "c", 14, "critical threshold in `days` before expiration date")
	rootCmd.PersistentFlags().StringVar(&rootFile, "root-file", "", "root certificate `file` (default system root certificate file)")
	rootCmd.PersistentFlags().BoolVar(&enableSSLCertDir, "enable-ssl-cert-dir", false, "enable system default certificate directories or environment variable SSL_CERT_DIR")
	rootCmd.PersistentFlags().StringVar(&dnType, "dn-type", "loose", "Distinguished Name Type. 'strict' (RFC 4514), 'loose' (with space), or 'openssl'")
	rootCmd.PersistentFlags().CountVarP(&verbose, "verbose", "v", "verbose mode. Multiple -v options increase the verbosity. The maximum is 3.")
}

func parseDNType(dnType string) (x509util.DNType, error) {
	var t x509util.DNType
	switch strings.ToLower(dnType) {
	case "strict":
		t = x509util.StrictDN
	case "loose":
		t = x509util.LooseDN
	case "openssl":
		t = x509util.OpenSSLDN
	default:
		return 0, errors.New("unknown Distinguished Name Type in '--dn-type' option")
	}
	return t, nil
}
