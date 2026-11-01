#!/bin/sh
# Включает Transit и создаёт два ключа (derived: контекст = отпечаток).
set -e
export VAULT_ADDR=http://vault:8200 VAULT_TOKEN=${VAULT_TOKEN:-esign-root}
until vault status >/dev/null 2>&1; do sleep 1; done
vault secrets list | grep -q '^transit/' || vault secrets enable transit
for k in esign-container esign-pin; do
  vault read "transit/keys/$k" >/dev/null 2>&1 || vault write -f "transit/keys/$k" type=aes256-gcm96 derived=true exportable=false
done
# Политика сервиса: только encrypt/decrypt/rewrap (для прода — отдельный токен с этой политикой)
vault policy write esign - <<'P'
path "transit/encrypt/esign-*" { capabilities = ["update"] }
path "transit/decrypt/esign-*" { capabilities = ["update"] }
path "transit/rewrap/esign-*"  { capabilities = ["update"] }
P
vault token create -policy=esign -id="${ESIGN_VAULT_TOKEN:-esign-service-token}" -ttl=768h >/dev/null 2>&1 || true
echo "Vault Transit готов"
