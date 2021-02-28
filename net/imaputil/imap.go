// Copyright 2010, 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package is a modification of the net.smtp package.
// See also:
//     https://golang.org/src/net/smtp/smtp.go

package imaputil

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

var tagNumber = 0

// A Client represents a client connection to an IMAP server.
type Client struct {
	// Text is the textproto.Conn used by the Client. It is exported to allow for
	// clients to add extensions.
	Text *textproto.Conn
	// keep a reference to the connection so it can be used to create a TLS
	// connection later
	conn net.Conn
	// whether the Client is using TLS
	tls bool
	// map of supported capability
	capability map[string]string
}

// Dial returns a new Client connected to an IMAP server at addr.
// The addr must include a port, as in "mail.example.com:443".
func Dial(network string, addr string, timeout time.Duration) (*Client, error) {
	dialer := net.Dialer{
		Timeout: timeout,
	}
	conn, err := dialer.Dial(network, addr)
	if err != nil {
		return nil, err
	}
	return NewClient(conn)
}

// NewClient returns a new Client using an existing connection.
func NewClient(conn net.Conn) (*Client, error) {
	text := textproto.NewConn(conn)
	_, err := text.ReadLine()
	if err != nil {
		text.Close()
		return nil, err
	}
	c := &Client{Text: text, conn: conn}
	_, c.tls = conn.(*tls.Conn)
	return c, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	return c.Text.Close()
}

// cmd is a convenience function that sends a command and returns the response
func (c *Client) cmd(format string, args ...interface{}) (string, error) {
	tag := fmt.Sprintf("A%06d", tagNumber)
	tagNumber++
	cmdString := fmt.Sprintf(format, args...)
	id, err := c.Text.Cmd("%s %s", tag, cmdString)
	if err != nil {
		return "", err
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	msg, err := c.readResponse(tag)
	return msg, err
}

func (c *Client) readResponse(tag string) (message string, err error) {
	for {
		line, err := c.Text.ReadLine()
		if err != nil {
			return "", err
		}
		if strings.HasPrefix(line, "*") {
			line = strings.TrimLeft(line, "* ")
			if message == "" {
				message = line
			} else {
				message += "\n" + line
			}
		} else if strings.HasPrefix(line, "+") {
			line = strings.TrimLeft(line, "+ ")
			message += " " + line
		} else if strings.HasPrefix(line, tag) {
			resp := strings.SplitN(line, " ", 3)
			if resp[1] != "OK" {
				message = "command error"
				if len(resp) == 3 {
					message = resp[2]
				}
				return "", fmt.Errorf("imap: %s", message)
			}
			break
		} else {
			break
		}
	}
	return message, nil
}

// Capability sends the CAPABILITY command to the server.
func (c *Client) Capability() error {
	msg, err := c.cmd("CAPABILITY")
	if err != nil {
		return err
	}
	capability := make(map[string]string)
	capabilityList := strings.Split(msg, " ")
	if len(capabilityList) > 0 {
		for _, c := range capabilityList[2:] {
			capability[c] = ""
		}
	}
	c.capability = capability
	return err
}

// StartTLS sends the STARTTLS command and encrypts all further communication.
// Only servers that advertise the STARTTLS extension support this function.
func (c *Client) StartTLS(config *tls.Config) error {
	if err := c.Capability(); err != nil {
		return err
	}
	_, ok := c.capability["STARTTLS"]
	if !ok {
		return errors.New("STARTTLS: STARTTLS command not supported")
	}
	_, err := c.cmd("STARTTLS")
	if err != nil {
		return err
	}
	c.conn = tls.Client(c.conn, config)
	c.Text = textproto.NewConn(c.conn)
	c.tls = true
	return c.Capability()
}

// TLSConnectionState returns the client's TLS connection state.
// The return values are their zero values if StartTLS did
// not succeed.
func (c *Client) TLSConnectionState() (state tls.ConnectionState, ok bool) {
	tc, ok := c.conn.(*tls.Conn)
	if !ok {
		return
	}
	return tc.ConnectionState(), true
}

// Logout sends the LOGOUT command and closes the connection to the server.
func (c *Client) Logout() error {
	_, err := c.cmd("LOGOUT")
	if err != nil {
		return err
	}
	return c.Text.Close()
}
