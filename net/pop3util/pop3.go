// Copyright 2010, 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package is a modification of the net.smtp package.
// See also:
//     https://golang.org/src/net/smtp/smtp.go

package pop3util

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// A Client represents a client connection to a POP3 server.
type Client struct {
	// Text is the textproto.Conn used by the Client. It is exported to allow for
	// clients to add extensions.
	Text *textproto.Conn
	// keep a reference to the connection so it can be used to create a TLS
	// connection later
	conn net.Conn
	// whether the Client is using TLS
	tls bool
	// map of supported capabilities
	capability map[string]string
}

// Dial returns a new Client connected to a POP3 server at addr.
// The addr must include a port, as in "mail.example.com:110".
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
func (c *Client) cmd(wantResponse bool, format string, args ...interface{}) (string, error) {
	id, err := c.Text.Cmd(format, args...)
	if err != nil {
		return "", err
	}
	c.Text.StartResponse(id)
	defer c.Text.EndResponse(id)
	msg, err := c.readResponse(wantResponse)
	return msg, err
}

func (c *Client) readResponse(wantResponse bool) (message string, err error) {
	line, err := c.Text.ReadLine()
	if err != nil {
		return "", err
	}
	resp := strings.SplitN(line, " ", 2)
	if resp[0] != "+OK" {
		message = "command error"
		if len(resp) == 2 {
			message = resp[1]
		}
		return "", fmt.Errorf("pop3: %s", message)
	}

	if !wantResponse {
		return message, nil
	}

	for {
		moreMessage, err := c.Text.ReadLine()
		if err != nil {
			return "", err
		}
		if moreMessage == "." {
			break
		}
		message += "\n" + moreMessage
	}

	return
}

// Capa sends the CAPA command to the server.
func (c *Client) Capa() error {
	msg, err := c.cmd(true, "CAPA")
	if err != nil {
		return err
	}
	ext := make(map[string]string)
	extList := strings.Split(msg, "\n")
	if len(extList) > 1 {
		extList = extList[1:]
		for _, line := range extList {
			if line == "." {
				break
			}
			args := strings.SplitN(line, " ", 2)
			if len(args) > 1 {
				ext[args[0]] = args[1]
			} else {
				ext[args[0]] = ""
			}
		}
	}
	c.capability = ext
	return err
}

// StartTLS sends the STARTTLS command and encrypts all further communication.
// Only servers that advertise the STARTTLS extension support this function.
func (c *Client) StartTLS(config *tls.Config) error {
	if err := c.Capa(); err != nil {
		return err
	}
	_, ok := c.capability["STLS"]
	if !ok {
		return errors.New("pop3: STLS command not supported")
	}
	_, err := c.cmd(false, "STLS")
	if err != nil {
		return err
	}
	c.conn = tls.Client(c.conn, config)
	c.Text = textproto.NewConn(c.conn)
	c.tls = true
	return c.Capa()
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

// Quit sends the QUIT command and closes the connection to the server.
func (c *Client) Quit() error {
	_, err := c.cmd(false, "QUIT")
	if err != nil {
		return err
	}
	return c.Text.Close()
}
