#!/bin/sh
# Copyright 2021 HEARTBEATS Corporation. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PRIVATE_KEY_DIR=test/testdata/pki/private
CA_CERT_DIR=test/testdata/pki/root-ca
CERT_DIR=test/testdata/pki/cert/valid

source scripts/pkilib.sh

gen_ocsp_responder_cert() {
  local issuer_name=$1
  local name=$2
  local subject=$3
  local days=$4

  ca_key_file=${PRIVATE_KEY_DIR}/${issuer_name}.pem
  ca_cert_file=$(_lookup_file ${CA_CERT_DIR} ${CERT_DIR} ${issuer_name}.pem)
  key_file=${PRIVATE_KEY_DIR}/${name}.pem
  csr_file=${CERT_DIR}/${name}.csr
  cert_file=${CERT_DIR}/${name}.pem

  _gen_ocsp_responder_cert ${ca_key_file} ${ca_cert_file} ${key_file} ${csr_file} ${cert_file} "${subject}" ${days}
}

# Intermediate CA A RSA OCSP Responder Certificate
gen_ocsp_responder_cert ca-intermediate-a-rsa ca-intermediate-a-rsa-ocsp-responder "/CN=Intermediate CA A RSA OCSP Responder" 365
