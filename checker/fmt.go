// Copyright 2022 HEARTBEATS Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package checker

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// output is an io.Writer. It's os.Stdout by default.
var output io.Writer

func init() {
	output = os.Stdout
}

// SetOutput sets the output.
func SetOutput(w io.Writer) {
	output = w
}

// GetOutput gets the output.
func GetOutput() io.Writer {
	return output
}

// Print formats using the default formats for its operands and writes to the specified output.
// Spaces are added between operands when neither is a string.
// It returns the number of bytes written and any write error encountered.
func Print(a ...interface{}) (n int, err error) {
	return fmt.Fprint(output, a...)
}

// Printf formats according to a format specifier and writes to the specified output.
// It returns the number of bytes written and any write error encountered.
func Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(output, format, a...)
}

// Println formats using the default formats for its operands and writes to the specified output.
// Spaces are always added between operands and a newline is appended.
// It returns the number of bytes written and any write error encountered.
func Println(a ...interface{}) (n int, err error) {
	return fmt.Fprintln(output, a...)
}

// printIndentedLine writes an indented line.
func printIndentedLine(indent int, format string, a ...interface{}) {
	var indentString = strings.Repeat(" ", indent)
	Print(indentString)
	Printf(format, a...)
	Print("\n")
}

// printKeyValueIfExists writes the line like `key: value` if a value exists.
func printKeyValueIfExists(indent int, key, value string) {
	if value == "" {
		return
	}
	var indentString = strings.Repeat(" ", indent)
	Print(indentString)
	Print(key)
	Print(": ")
	Print(value)
	Print("\n")
}

// printKeyValueIfExists writes the line like `key:\n    value\n...` if values exists.
func printKeyValuesIfExists(indent int, key string, values []string) {
	if values == nil {
		return
	}
	var indentString = strings.Repeat(" ", indent)
	Print(indentString)
	Print(key)
	Print(":\n")
	for _, value := range values {
		Print(indentString)
		Print("    ")
		Print(value)
		Print("\n")
	}
}

// printKey writes the line like `key:`.
func printKey(indent int, key string) {
	var indentString = strings.Repeat(" ", indent)
	Print(indentString)
	Print(key)
	Print(":\n")
}
