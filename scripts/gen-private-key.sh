#!/bin/sh
# Copyright 2021 HEARTBEATS Corporation. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PRIVATE_KEY_DIR=test/testdata/pki/private

source scripts/pkilib.sh

gen_ca_private_key() {
  local name=$1
  local algo=$2

  key_file=${PRIVATE_KEY_DIR}/${name}.pem

  _gen_ca_private_key ${key_file} ${algo}
}

gen_server_private_key() {
  local name=$1
  local algo=$2
  local cipher=$3
  local pass_file=$4

  key_file=${PRIVATE_KEY_DIR}/${name}.pem
  if [[ -n ${pass_file} ]]; then
    pass_file=${PRIVATE_KEY_DIR}/${pass_file}
  fi

  _gen_server_private_key ${key_file} ${algo} ${cipher} ${pass_file}
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


# server-a.test RSA Private Key and Encrypted Key
gen_server_private_key server-a-rsa rsa aes-128-cbc password.txt

# server-a.test ECDSA Private Key and Encrypted Key
gen_server_private_key server-a-ecdsa ecdsa aes-128-cbc password.txt

# server-a.test Ed25519 Private Key and Encrypted Key
gen_server_private_key server-a-ed25519 ed25519 aes-128-cbc password.txt

# server-a.test Ed488 Private Key and Encrypted Key
gen_server_private_key server-a-ed488 ed488 aes-128-cbc password.txt


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


# variables PEM format
# No EOL
cat ${PRIVATE_KEY_DIR}/server-a-rsa.pem | awk '!/-----END/ {print} /-----END/ {printf("%s", $0)}' > ${PRIVATE_KEY_DIR}/misc-no-eol.pem

# Explanatory Text
echo "Pre Explanatory Text" > ${PRIVATE_KEY_DIR}/misc-explanatory-text.pem
cat ${PRIVATE_KEY_DIR}/server-a-rsa.pem >> ${PRIVATE_KEY_DIR}/misc-explanatory-text.pem
echo "Post Explanatory Text" >> ${PRIVATE_KEY_DIR}/misc-explanatory-text.pem
