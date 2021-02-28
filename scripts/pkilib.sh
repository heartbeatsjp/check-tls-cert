# Copyright 2021 HEARTBEATS Corporation. All rights reserved.
# Use of this source code is governed by a BSD-style
# license that can be found in the LICENSE file.

LANG=C
export LANG

_gen_ca_private_key() {
  local key_file=$1
  local algo=$2

  echo "Creating Private Key: ${key_file}"

  case ${algo} in
    "rsa")
      echo "openssl genrsa -out ${key_file} 4096"
      openssl genrsa -out ${key_file} 4096
      ;;
    "ecdsa")
      echo "openssl ecparam -out ${key_file} -name secp384r1 -genkey"
      openssl ecparam -out ${key_file} -name secp384r1 -genkey
      ;;
    *)
      echo "Unknown algorithm"
      exit 1
  esac

  echo "Done."
  echo ""
}

_gen_server_private_key() {
  local key_file=$1
  local algo=$2

  traditional_key_file=${key_file%.key}-traditional.key

  echo "Creating Private Key: ${key_file}"

  case ${algo} in
    "rsa")
      echo "openssl genpkey -out ${key_file} -algorithm RSA -pkeyopt rsa_keygen_bits:2048"
      openssl genpkey -out ${key_file} -algorithm RSA -pkeyopt rsa_keygen_bits:2048
      echo "openssl pkey -in ${key_file} -traditional -out ${traditional_key_file}"
      openssl pkey -in ${key_file} -traditional -out ${traditional_key_file}
      ;;
    "ecdsa")
      echo "openssl genpkey -out ${key_file} -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1"
      openssl genpkey -out ${key_file} -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1
      echo "openssl pkey -in ${key_file} -traditional -out ${traditional_key_file}"
      openssl pkey -in ${key_file} -traditional -out ${traditional_key_file}
      ;;
    "ed25519")
      echo "openssl genpkey -out ${key_file} -algorithm ED25519"
      openssl genpkey -out ${key_file} -algorithm ED25519
      ;;
    "ed488")
      echo "openssl genpkey -out ${key_file} -algorithm ED448"
      openssl genpkey -out ${key_file} -algorithm ED448
      ;;
    *)
      echo "Unknown algorithm"
      exit 1
  esac

  echo "Done."
  echo ""
}

_gen_root_ca_cert() {
  local ca_key_file=$1
  local cert_file=$2
  local subject=$3
  local days=$4
  local startdate=$5

  if [[ -n "${startdate}" ]]; then
    now=$(date)
    sudo date -s ${startdate} -u > /dev/null
  fi

  echo "Creating Root CA Certificate: ${cert_file}"
  openssl req -new -key ${ca_key_file} -sha384 -x509 -days ${days} -subj "${subject}" \
    -addext keyUsage=critical,digitalSignature,keyCertSign,cRLSign \
    -out ${cert_file}
  openssl x509 -in ${cert_file} -noout -subject -startdate -enddate
  echo "Done."
  echo ""

  if [[ -n "${startdate}" ]]; then
    sudo date -s "${now}" > /dev/null
    touch ${cert_file}
  fi
}

_gen_intermediate_ca_cert() {
  local ca_key_file=$1
  local ca_cert_file=$2
  local key_file=$3
  local csr_file=$4
  local cert_file=$5
  local subject=$6
  local days=$7
  local startdate=$8

  if [[ -n "${startdate}" ]]; then
    now=$(date)
    sudo date -s ${startdate} -u > /dev/null
  fi

  echo "Creating Intermediate Certificate: ${cert_file}"
  openssl req -new -nodes -key ${key_file} -sha384 -subj "${subject}" -out ${csr_file}
  openssl x509 -req -in ${csr_file} -days ${days} \
    -CA ${ca_cert_file} -CAkey ${ca_key_file} -CAcreateserial -sha384 \
    -extfile <(cat <<EOT
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
keyUsage=critical,digitalSignature,keyCertSign,cRLSign
extendedKeyUsage=serverAuth,clientAuth
basicConstraints=critical,CA:true
EOT
) \
    -out ${cert_file}
  openssl x509 -in ${cert_file} -noout -startdate -enddate
  rm ${csr_file}
  rm ${ca_cert_file%.crt}.srl
  echo "Done."
  echo ""

  if [[ -n "${startdate}" ]]; then
    sudo date -s "${now}" > /dev/null
    touch ${cert_file}
  fi
}

_gen_server_cert() {
  local ca_key_file=$1
  local ca_cert_file=$2
  local key_file=$3
  local csr_file=$4
  local cert_file=$5
  local domainname=$6
  local days=$7
  local startdate=$8

  if [[ -n "${startdate}" ]]; then
    now=$(date)
    sudo date -s ${startdate} -u > /dev/null
  fi

  echo "Creating Server Certificate: ${cert_file}"
  openssl req -new -nodes -key ${key_file} -sha256 -subj "/CN=${domainname}" \
    -out ${csr_file}
  openssl x509 -req -in ${csr_file} -days ${days} \
    -CA ${ca_cert_file} -CAkey ${ca_key_file} -CAcreateserial -sha256 \
    -extfile <(cat <<EOT
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=DNS:${domainname},DNS:www.${domainname}
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
basicConstraints=CA:FALSE
EOT
) \
    -out ${cert_file}
  openssl x509 -in ${cert_file} -noout -startdate -enddate
  rm ${csr_file}
  rm ${ca_cert_file%.crt}.srl
  echo "Done."
  echo ""

  if [[ -n "${startdate}" ]]; then
    sudo date -s "${now}" > /dev/null
    touch ${cert_file}
  fi
}

_lookup_file() {
  local ca_cert_dir=$1
  local cert_dir=$2
  local filename=$3

  if [[ -f ${ca_cert_dir}/${filename} ]]; then
    echo "${ca_cert_dir}/${filename}"
  elif [[ -f ${cert_dir}/${filename} ]]; then
    echo "${cert_dir}/${filename}"
  else
    echo "ERROR: Unable to find ${filename}" 1>&2
    exit 1
  fi
}

