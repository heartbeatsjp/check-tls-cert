#!/bin/sh
# Copyright 2021 HEARTBEATS Corporation. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PRIVATE_KEY_DIR=test/testdata/pki/private

source scripts/pkilib.sh

gen_ca_private_key() {
  local name=$1
  local algo=$2

  key_file=${PRIVATE_KEY_DIR}/${name}.key

  _gen_ca_private_key ${key_file} ${algo}
}

gen_server_private_key() {
  local name=$1
  local algo=$2

  key_file=${PRIVATE_KEY_DIR}/${name}.key

  _gen_server_private_key ${key_file} ${algo}
}


# Root CA G1 RSA Private Key
gen_ca_private_key ca-root-g1-rsa rsa

# Root CA G2 RSA Private Key
gen_ca_private_key ca-root-g2-rsa rsa

# Root CA G2 ECDSA Private Key
gen_ca_private_key ca-root-g2-ecdsa ecdsa


# Intermediate CA A RSA Private Key
gen_ca_private_key ca-intermediate-a-rsa rsa

# Intermediate CA B RSA Private Key
gen_ca_private_key ca-intermediate-b-rsa rsa

# Intermediate CA ECDSA Private Key
gen_ca_private_key ca-intermediate-ecdsa ecdsa


# server-a.test RSA Private Key
gen_server_private_key server-a-rsa rsa

# server-a.test ECDSA Private Key
gen_server_private_key server-a-ecdsa ecdsa

# server-a.test Ed25519 Private Key
gen_server_private_key server-a-ed25519 ed25519

# server-a.test Ed488 Private Key
gen_server_private_key server-a-ed488 ed488


# server-b.test RSA Private Key
gen_server_private_key server-b-rsa rsa

# server-b.test ECDSA Private Key
gen_server_private_key server-b-ecdsa ecdsa

# server-b.test Ed25519 Private Key
gen_server_private_key server-b-ed25519 ed25519

# server-b.test Ed488 Private Key
gen_server_private_key server-b-ed488 ed488


# server-c.test RSA Private Key
gen_server_private_key server-c-rsa rsa

# server-c.test ECDSA Private Key
gen_server_private_key server-c-ecdsa ecdsa

# server-c.test Ed25519 Private Key
gen_server_private_key server-c-ed25519 ed25519

# server-c.test Ed488 Private Key
gen_server_private_key server-c-ed488 ed488


# Intermediate CA A RSA OCSP Responder Private Key
gen_server_private_key ca-intermediate-a-rsa-ocsp-responder rsa
