#!/usr/bin/env bash
# A throwaway CA and provider leaf for the synthetic Telegram endpoint, written into DIR. Never a real key.
set -euo pipefail
cd "$1"
ec=(-newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes)
openssl req -x509 "${ec[@]}" -days 1 -subj /CN=fixture-ca -keyout ca.key -out ca.pem \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
openssl req "${ec[@]}" -subj /CN=api.telegram.org -keyout provider.key -out provider.csr 2>/dev/null
printf '%s\n' subjectAltName=DNS:api.telegram.org,DNS:localhost basicConstraints=critical,CA:FALSE \
    keyUsage=critical,digitalSignature extendedKeyUsage=serverAuth \
    subjectKeyIdentifier=hash authorityKeyIdentifier=keyid >ext
openssl x509 -req -in provider.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 1 -extfile ext \
    -out provider.pem 2>/dev/null
rm -f ca.key ca.srl provider.csr ext
