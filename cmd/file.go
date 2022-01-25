// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"fmt"
	"os"

	file "github.com/heartbeatsjp/check-tls-cert/internal/file"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var (
	keyFile      string
	certFile     string
	chainFile    string
	caFile       string
	passwordFile string

	fileCmd = &cobra.Command{
		Use:   "file",
		Short: "Checks TLS certificate files.",
		RunE: func(cmd *cobra.Command, args []string) error {
			dntype, err := parseDNType(dnType)
			if err != nil {
				fmt.Printf("ERROR: %s\n", err.Error())
			}

			keyFile, _ = homedir.Expand(keyFile)
			certFile, _ = homedir.Expand(certFile)
			chainFile, _ = homedir.Expand(chainFile)
			rootFile, _ = homedir.Expand(rootFile)
			passwordFile, _ = homedir.Expand(passwordFile)

			code, err := file.Run(hostname, keyFile, certFile, chainFile, rootFile, caFile, passwordFile, warning, critical, enableSSLCertDir, dntype, verbose)
			if err != nil {
				fmt.Printf("ERROR: %s\n", err.Error())
			}
			os.Exit(code)
			return nil
		},
	}
)

func init() {
	fileCmd.Flags().StringVarP(&hostname, "hostname", "H", "", "`hostname` for verifying certificate. (required)")
	fileCmd.MarkFlagRequired("hostname")
	fileCmd.Flags().StringVarP(&keyFile, "key-file", "k", "", "private key `file`. (required)")
	fileCmd.MarkFlagRequired("key-file")
	fileCmd.Flags().StringVarP(&certFile, "cert-file", "f", "", "certificates `file`. It includes a server certificate and intermediate certificates. (required)")
	fileCmd.MarkFlagRequired("cert-file")
	fileCmd.Flags().StringVarP(&chainFile, "chain-file", "C", "", "certificate chain `file`. It includes intermediate certificates. Used for the SSLCertificateChainFile directive in old Apache HTTP Server.")
	fileCmd.Flags().StringVar(&caFile, "ca-file", "", "trusted CA certificates `file`. It includes intermediate certificates and a root certificate. Used for the ssl_trusted_certificate directive in nginx and the SSLCACertificateFile directive in Apache HTTP Server.")
	fileCmd.Flags().StringVarP(&passwordFile, "password-file", "P", "", "password `file` for the private key file if the private key file is encrypted. If it is not specified, you will be prompted to enter the password.")

	rootCmd.AddCommand(fileCmd)
}
