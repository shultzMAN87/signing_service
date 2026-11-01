#!/usr/bin/env bash
# Тестовый УЦ и ключ ГОСТ Р 34.10-2012 (256) в PFX. Только для стенда.
set -euo pipefail
OUT=${1:-./testkeys}; PIN=${2:-12345678}; CN=${3:-"ООО Ромашка (тест)"}
HERE=$(cd "$(dirname "$0")/.." && pwd)
export OPENSSL_CONF=$HERE/dev/gost.cnf
mkdir -p "$OUT"; cd "$OUT"
if [ ! -f ca.key ]; then
  openssl genpkey -algorithm gost2012_256 -pkeyopt paramset:A -out ca.key
  openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=Test GOST CA/O=Test" -md_gost12_256 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign
fi
NAME=${4:-org}
openssl genpkey -algorithm gost2012_256 -pkeyopt paramset:A -out $NAME.key
openssl req -new -key $NAME.key -out $NAME.csr -subj "/CN=$CN/O=$CN" -md_gost12_256 -utf8
printf "keyUsage=critical,digitalSignature,nonRepudiation,keyEncipherment,keyAgreement\nextendedKeyUsage=emailProtection\n" > ext.cnf
openssl x509 -req -in $NAME.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 365 -out $NAME.crt -md_gost12_256 -extfile ext.cnf 2>/dev/null
openssl pkcs12 -export -inkey $NAME.key -in $NAME.crt -out $NAME.pfx -passout pass:$PIN \
  -keypbe gost89 -certpbe gost89 -macalg md_gost12_256
rm -f $NAME.csr ext.cnf
echo "$OUT/$NAME.pfx (PIN $PIN)"
