#!/bin/sh
# Copyright 2021 HEARTBEATS Corporation. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PRIVATE_KEY_DIR=test/testdata/pki/private
CA_CERT_DIR=test/testdata/pki/root-ca

source scripts/pkilib.sh

gen_root_ca_cert() {
  local name=$1
  local subject=$2
  local days=$3
  local startdate=$4

  ca_key_file=${PRIVATE_KEY_DIR}/${name}.pem
  cert_file=${CA_CERT_DIR}/${name}.pem

  _gen_root_ca_cert ${ca_key_file} ${cert_file} "${subject}" ${days} ${startdate}
}

gen_intermediate_ca_cert() {
  local issuer_name=$1
  local name=$2
  local subject=$3
  local days=$4
  local suffix=$5
  local startdate=$6

  ca_key_file=${PRIVATE_KEY_DIR}/${issuer_name}.pem
  ca_cert_file=${CA_CERT_DIR}/${issuer_name}.pem
  key_file=${PRIVATE_KEY_DIR}/${name}.pem
  csr_file=${CA_CERT_DIR}/${name}.csr
  cert_file=${CA_CERT_DIR}/${name}.pem

  if [[ -n "${suffix}" ]]; then
    cert_file=${CA_CERT_DIR}/${name}-${suffix}.pem
  fi

  _gen_intermediate_ca_cert ${ca_key_file} ${ca_cert_file} ${key_file} ${csr_file} ${cert_file} "${subject}" ${days} ${startdate}
}


# Root CA G1 Certificate
gen_root_ca_cert ca-root-g1-rsa "/CN=ROOT CA G1 RSA" 10957 '2005-01-01'

# Root CA G2 RSA Certificate
gen_root_ca_cert ca-root-g2-rsa "/CN=ROOT CA G2 RSA" 7305 '2015-01-01'

# Root CA G2 ECDSA Certificate
gen_root_ca_cert ca-root-g2-ecdsa "/CN=ROOT CA G2 ECDSA" 7305 '2015-01-01'

# Root CA G2 RSA Certificate (Cross-Signing)
gen_intermediate_ca_cert ca-root-g1-rsa ca-root-g2-rsa "/CN=ROOT CA G2 RSA" 7305 cross '2015-01-01'

# Root CA G2 ECDSA Certificate (Cross-Signing)
gen_intermediate_ca_cert ca-root-g1-rsa ca-root-g2-ecdsa "/CN=ROOT CA G2 ECDSA" 7305 cross '2015-01-01'


cat ${CA_CERT_DIR}/{ca-root-g1-rsa,ca-root-g2-rsa,ca-root-g2-ecdsa}.pem > ${CA_CERT_DIR}/ca-root.pem

exit

