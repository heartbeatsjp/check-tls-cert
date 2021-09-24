#!/bin/sh
# Copyright 2021 HEARTBEATS Corporation. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PRIVATE_KEY_DIR=test/testdata/pki/private
CA_CERT_DIR=test/testdata/pki/root-ca
CERT_DIR=test/testdata/pki/cert/valid

source scripts/pkilib.sh

gen_intermediate_ca_cert() {
  local issuer_name=$1
  local name=$2
  local subject=$3
  local days=$4

  ca_key_file=${PRIVATE_KEY_DIR}/${issuer_name}.key
  ca_cert_file=$(_lookup_file ${CA_CERT_DIR} ${CERT_DIR} ${issuer_name}.crt)
  key_file=${PRIVATE_KEY_DIR}/${name}.key
  csr_file=${CERT_DIR}/${name}.csr
  cert_file=${CERT_DIR}/${name}.crt

  _gen_intermediate_ca_cert ${ca_key_file} ${ca_cert_file} ${key_file} ${csr_file} ${cert_file} "${subject}" ${days}
}

gen_server_cert() {
  local issuer_name=$1
  local name=$2
  local domainname=$3
  local days=$4

  ca_key_file=${PRIVATE_KEY_DIR}/${issuer_name}.key
  ca_cert_file=${CERT_DIR}/${issuer_name}.crt
  key_file=${PRIVATE_KEY_DIR}/${name}.key
  csr_file=${CERT_DIR}/${name}.csr
  cert_file=${CERT_DIR}/${name}.crt

  _gen_server_cert ${ca_key_file} ${ca_cert_file} ${key_file} ${csr_file} ${cert_file} ${domainname} ${days}
}


# Intermediate CA A RSA Certificate
gen_intermediate_ca_cert ca-root-g2-rsa ca-intermediate-a-rsa "/CN=Intermediate CA A RSA" 3653

# server-a.test (RSA)
gen_server_cert ca-intermediate-a-rsa server-a-rsa "server-a.test" 365

# server-a.test (ECDSA)
gen_server_cert ca-intermediate-a-rsa server-a-ecdsa "server-a.test" 365

# server-a.test (Ed25519)
gen_server_cert ca-intermediate-a-rsa server-a-ed25519 "server-a.test" 365

# server-a.test (Ed488)
gen_server_cert ca-intermediate-a-rsa server-a-ed488 "server-a.test" 365


# Intermediate CA B RSA Certificate
gen_intermediate_ca_cert ca-root-g2-rsa ca-intermediate-b-rsa "/CN=Intermediate CA B RSA" 3653

# server-b.test (RSA)
gen_server_cert ca-intermediate-b-rsa server-b-rsa "server-b.test" 365

# server-b.test (ECDSA)
gen_server_cert ca-intermediate-b-rsa server-b-ecdsa "server-b.test" 365

# server-b.test (Ed25519)
gen_server_cert ca-intermediate-b-rsa server-b-ed25519 "server-b.test" 365

# server-b.test (Ed488)
gen_server_cert ca-intermediate-b-rsa server-b-ed488 "server-b.test" 365


# Intermediate CA ECDSA Certificate
gen_intermediate_ca_cert ca-root-g2-ecdsa ca-intermediate-ecdsa "/CN=Intermediate CA ECDSA" 3653

# server-c.test (RSA)
gen_server_cert ca-intermediate-ecdsa server-c-rsa "server-c.test" 365

# server-c.test (ECDSA)
gen_server_cert ca-intermediate-ecdsa server-c-ecdsa "server-c.test" 365

# server-c.test (Ed25519)
gen_server_cert ca-intermediate-ecdsa server-c-ed25519 "server-c.test" 365

# server-c.test (Ed488)
gen_server_cert ca-intermediate-ecdsa server-c-ed488 "server-c.test" 365


# variables PEM format
# No EOL
cat ${CERT_DIR}/server-a-rsa.crt | awk '!/-----END/ {print} /-----END/ {printf("%s", $0)}' > ${CERT_DIR}/misc-no-eol.crt 

# Explanatory Text
echo "Pre Explanatory Text" > ${CERT_DIR}/misc-explanatory-text.crt
cat ${CERT_DIR}/server-a-rsa.crt >> ${CERT_DIR}/misc-explanatory-text.crt
echo "Post Explanatory Text" >> ${CERT_DIR}/misc-explanatory-text.crt
