// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"fmt"
	"os"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	filecmd "github.com/heartbeatsjp/check-tls-cert/internal/file"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var (
	keyFile        string
	certFile       string
	chainFile      string
	caFile         string
	passwordFile   string
	fileCmdOptions filecmd.FileCommandOptions

	fileCmd = &cobra.Command{
		Use:   "file",
		Short: "Checks TLS certificate files.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			keyFile, _ = homedir.Expand(keyFile)
			certFile, _ = homedir.Expand(certFile)
			chainFile, _ = homedir.Expand(chainFile)
			passwordFile, _ = homedir.Expand(passwordFile)

			fileCmdOptions = filecmd.FileCommandOptions{
				Hostname:         hostname,
				KeyFile:          keyFile,
				CertFile:         certFile,
				ChainFile:        chainFile,
				CAFile:           caFile,
				PasswordFile:     passwordFile,
				Warning:          warning,
				Critical:         critical,
				RootFile:         rootFile,
				EnableSSLCertDir: enableSSLCertDir,
				OutputFormat:     outputFormat,
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := filecmd.Run(fileCmdOptions)
			if err != nil {
				switch outputFormat {
				case checker.JSONFormat:
					r := checker.NewResult(checker.NewErrorSummary(err), nil)
					r.PrintJSON()
					os.Exit(checker.UNKNOWN.Code())
				default:
					fmt.Printf("Error: %s\n", err.Error())
					os.Exit(checker.UNKNOWN.Code())
				}
				return err
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
	fileCmd.Flags().IntVarP(&warning, "warning", "w", 28, "warning threshold in `days` before expiration date")
	fileCmd.Flags().IntVarP(&critical, "critical", "c", 14, "critical threshold in `days` before expiration date")
	fileCmd.Flags().SortFlags = false

	rootCmd.AddCommand(fileCmd)
}
