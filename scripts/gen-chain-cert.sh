#!/bin/sh
# Copyright 2021 HEARTBEATS Corporation. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

PRIVATE_KEY_DIR=test/testdata/pki/private
CA_CERT_DIR=test/testdata/pki/root-ca
VALID_CERT_DIR=test/testdata/pki/cert/valid
CHAIN_CERT_DIR=test/testdata/pki/chain


# Certificate Chain
cat ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    > ${CHAIN_CERT_DIR}/chain-a-rsa.pem

cat ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    ${CA_CERT_DIR}/ca-root-g2-rsa-cross.pem \
    > ${CHAIN_CERT_DIR}/chain-a-rsa-cross.pem

cat ${CA_CERT_DIR}/ca-root-g2-rsa-cross.pem \
    ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    > ${CHAIN_CERT_DIR}/invalid-chain-a-rsa-cross.pem

# Full chain
cat ${VALID_CERT_DIR}/server-a-rsa.pem \
    ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    > ${CHAIN_CERT_DIR}/fullchain-a-rsa.pem

cat ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    ${VALID_CERT_DIR}/server-a-rsa.pem \
    > ${CHAIN_CERT_DIR}/invalid-fullchain-a-rsa.pem

cat ${VALID_CERT_DIR}/server-a-rsa.pem \
    ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    ${CA_CERT_DIR}/ca-root-g2-rsa-cross.pem \
    > ${CHAIN_CERT_DIR}/fullchain-a-rsa-cross.pem

cat ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    ${CA_CERT_DIR}/ca-root-g2-rsa-cross.pem \
    ${VALID_CERT_DIR}/server-a-rsa.pem \
    > ${CHAIN_CERT_DIR}/fullchain-a-rsa-cross.pem

# Trusted Certificates
cat ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    ${CA_CERT_DIR}/ca-root-g2-rsa.pem \
    > ${CHAIN_CERT_DIR}/ca.pem

cat ${CA_CERT_DIR}/ca-root-g2-rsa.pem \
    ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    > ${CHAIN_CERT_DIR}/invalid-ca.pem

# Mixed file
cat ${VALID_CERT_DIR}/server-a-rsa.pem \
    ${VALID_CERT_DIR}/ca-intermediate-a-rsa.pem \
    ${PRIVATE_KEY_DIR}/server-a-rsa.pem \
    > ${CHAIN_CERT_DIR}/fullchain-a-rsa-private-key.pem
