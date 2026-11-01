#!/bin/sh
# Лицензия КриптоПро (без неё работает пробный период) и запуск от пользователя esign.
set -e
CPCONFIG=/opt/cprocsp/sbin/amd64/cpconfig
if [ -n "$CPRO_SERIAL" ]; then
  $CPCONFIG -license -set "$CPRO_SERIAL" >/dev/null && echo "КриптоПро: лицензия установлена"
fi
$CPCONFIG -license -view 2>/dev/null | head -3 || true
# Каталог ключей HDIMAGE пользователя esign — tmpfs (см. docker-compose.yml)
chown esign:esign /var/opt/cprocsp/keys/esign 2>/dev/null || true
chmod 700 /var/opt/cprocsp/keys/esign 2>/dev/null || true
exec setpriv --reuid=esign --regid=esign --init-groups /usr/local/bin/esign
