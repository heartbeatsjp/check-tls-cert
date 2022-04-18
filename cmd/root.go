// Copyright 2021 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cmd

import (
	"errors"
	"os"
	"strings"
	"time"

	"github.com/heartbeatsjp/check-tls-cert/checker"
	"github.com/heartbeatsjp/check-tls-cert/version"
	"github.com/heartbeatsjp/check-tls-cert/x509util"
	"github.com/mitchellh/go-homedir"
	"github.com/spf13/cobra"
)

var (
	hostname         string
	warning          int
	critical         int
	rootFile         string
	enableSSLCertDir bool
	dnTypeStr        string
	dnType           x509util.DNType
	verbose          int
	outputFormatStr  string
	outputFormat     checker.OutputFormat
	timestamp        string
	currentTime      time.Time

	rootCmd = &cobra.Command{
		Use:     "check-tls-cert",
		Short:   "check-tls-cert is a TLS certificate checker",
		Version: version.Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error

			rootFile, _ = homedir.Expand(rootFile)

			checker.SetVerbose(verbose)

			if dnType, err = parseDNType(dnTypeStr); err != nil {
				return err
			}
			checker.SetDNType(dnType)

			if outputFormat, err = parseOutputFormat(outputFormatStr); err != nil {
				return err
			}

			if currentTime, err = parseTimestamp(timestamp); err != nil {
				return err
			}
			checker.SetCurrentTime(currentTime)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Help()
			return nil
		},
	}
)

// Execute the `check-tls-cert` command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(checker.UNKNOWN.Code())
	}
}

func init() {
	cobra.EnableCommandSorting = false
	rootCmd.PersistentFlags().StringVar(&rootFile, "root-file", "", "root certificate `file` (default system root certificate file)")
	rootCmd.PersistentFlags().BoolVar(&enableSSLCertDir, "enable-ssl-cert-dir", false, "enable system default certificate directories or environment variable SSL_CERT_DIR")
	rootCmd.PersistentFlags().StringVar(&dnTypeStr, "dn-type", "loose", "Distinguished Name type. 'strict' (RFC 4514), 'loose' (with space), or 'openssl'")
	rootCmd.PersistentFlags().CountVarP(&verbose, "verbose", "v", "verbose mode. Multiple -v options increase the verbosity. The maximum is 3.")
	rootCmd.PersistentFlags().StringVarP(&outputFormatStr, "output-format", "O", "default", "output format. 'default' or 'json'")

	// The option `--timestamp`` is used for debugging.
	rootCmd.PersistentFlags().StringVar(&timestamp, "timestamp", "", "timestamp. This format is '2006-01-02T15:04:05+07:00'. (default a current time)")
	rootCmd.PersistentFlags().MarkHidden("timestamp")

	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false
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

func parseOutputFormat(outputFormatStr string) (f checker.OutputFormat, err error) {
	switch strings.ToLower(outputFormatStr) {
	case "default":
		f = checker.DefaultFormat
	case "json":
		f = checker.JSONFormat
	default:
		return checker.DefaultFormat, errors.New("unknown Output Format in '--output-format' option")
	}
	return f, nil
}

func parseTimestamp(timestampStr string) (time.Time, error) {
	if timestampStr == "" {
		return time.Now(), nil
	}
	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		return time.Now(), errors.New("invalid format in '--timestamp' option")
	}
	return timestamp, nil
}
