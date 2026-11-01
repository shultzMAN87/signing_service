#!/usr/bin/env bash
# Проверка стенда после `docker compose up`: загрузка ключа в два шага, подписи,
# шифрование/расшифровка, блокировка, аудит, метрики.
#   ./scripts/smoke.sh путь/к/ключу.pfx PIN [http://localhost:8800]
# Нужны только bash и curl (Linux, macOS, WSL, Git Bash).
set -euo pipefail
PFX=${1:?"укажите PFX"}; PIN=${2:?"укажите PIN"}; BASE=${3:-http://localhost:8800}
API=$BASE/api/v1
ADM="Authorization: Bearer admin-token-1"; ADM2="admin-token-2"
ERP="Authorization: Bearer erp-token"; EDO="Authorization: Bearer edo-token"; AUD="Authorization: Bearer audit-token"
OUT=smoke-out; mkdir -p "$OUT"
ok=0; fail=0
pass() { echo "  ✔ $1"; ok=$((ok+1)); }
bad()  { echo "  ✘ $1"; fail=$((fail+1)); }
json() { sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }
# то же, но тело ответа сохраняется в файл: save <файл> <аргументы curl>
save() { local f=$1; shift; curl -s -o "$f" -w '%{http_code}' "$@"; }
# файл не пустой и похож на CMS (DER начинается с 0x30)
is_cms() { [ -s "$1" ] && [ "$(head -c1 "$1" | od -An -tx1 | tr -d ' ')" = "30" ]; }

echo "1. Сервис"
curl -fsS "$API/health" && echo && pass "health"

echo "2. Загрузка ключа: шаг 1 — контейнер без PIN"
UP=$(curl -fsS -H "$ADM" -F "container=@$PFX" -F key_type=organization \
     -F 'clients=[{"id":"1c-erp","sign":true,"decrypt":true}]' "$API/keys/uploads")
ID=$(echo "$UP" | json upload_id); [ -n "$ID" ] && pass "upload_id $ID" || { bad "нет upload_id: $UP"; exit 1; }

echo "3. Шаг 2 — неверный PIN, затем верный"
[ "$(code -H "$ADM" -H 'Content-Type: application/json' -d '{"pin":"заведомо-неверный"}' "$API/keys/uploads/$ID/pin")" = 422 ] \
  && pass "неверный PIN отклонён (422)" || bad "неверный PIN не отклонён"
CARD=$(curl -sS -H "$ADM" -H 'Content-Type: application/json' -d "{\"pin\":\"$PIN\"}" "$API/keys/uploads/$ID/pin")
TP=$(echo "$CARD" | json thumbprint)
if [ -z "$TP" ]; then
  # ключ уже был загружен ранее — возьмём из ответа 409
  TP=$(echo "$CARD" | sed -n 's/.*Ключ \([0-9A-F]\{40\}\).*/\1/p')
  [ -n "$TP" ] && pass "ключ уже загружен: $TP" || { bad "установка: $CARD"; exit 1; }
else
  pass "ключ установлен: $TP (PIN заменён сервисом)"
fi

echo "4. Подписи"
printf 'Акт сверки №7 от %s\n' "$(date +%d.%m.%Y)" > "$OUT/akt.txt"
head -c 300000 /dev/urandom > "$OUT/doc.bin"
for ext in sgn sig p7s sign; do
  [ "$(save "$OUT/akt.txt.$ext" -H "$ERP" -F thumbprint=$TP -F "file=@$OUT/akt.txt" -F ext=$ext "$API/sign")" = 200 ] \
    && is_cms "$OUT/akt.txt.$ext" && pass "отделённая .$ext → $OUT/akt.txt.$ext" || bad "отделённая .$ext"
done
[ "$(save "$OUT/akt.txt.p7m" -H "$ERP" -F thumbprint=$TP -F "file=@$OUT/akt.txt" -F detached=false "$API/sign")" = 200 ] \
  && is_cms "$OUT/akt.txt.p7m" && pass "прикреплённая → $OUT/akt.txt.p7m" || bad "прикреплённая"
[ "$(save "$OUT/doc.bin.sgn.b64" -H "$ERP" -F thumbprint=$TP -F "file=@$OUT/doc.bin" -F encoding=base64 "$API/sign")" = 200 ] \
  && [ -s "$OUT/doc.bin.sgn.b64" ] && pass "файл 300 КБ, Base64 → $OUT/doc.bin.sgn.b64" || bad "Base64"
[ "$(code -H "$ERP" -H 'Content-Type: application/json' -d "{\"thumbprint\":\"$TP\",\"hash\":\"AAAA\",\"detached\":false}" "$API/sign")" = 400 ] \
  && pass "прикреплённая по хэшу запрещена (400)" || bad "проверка hash_requires_detached"

echo "5. Шифрование и расшифровка"
ENC=$(curl -fsS -H "$EDO" -H 'Content-Type: application/json' \
      -d "{\"recipients\":[\"$TP\"],\"text\":\"Тестовая секретная строка\",\"encoding\":\"base64\"}" "$API/encrypt")
DEC=$(curl -fsS -H "$ERP" -H 'Content-Type: application/json' -d "{\"thumbprint\":\"$TP\",\"data\":\"$ENC\",\"as_text\":true}" "$API/decrypt")
echo "$DEC" | grep -q 'Тестовая секретная строка' && pass "строка расшифрована" || bad "расшифровка: $DEC"
curl -fsS -H "$EDO" -F "recipients=$TP" -F "file=@$OUT/doc.bin" -o "$OUT/doc.bin.p7m.enc" "$API/encrypt"
curl -fsS -H "$ERP" -F "thumbprint=$TP" -F "file=@$OUT/doc.bin.p7m.enc" -o "$OUT/doc.bin.dec" "$API/decrypt"
cmp -s "$OUT/doc.bin" "$OUT/doc.bin.dec" && pass "файл 300 КБ расшифрован без искажений" || bad "файл расшифрован с искажениями"
[ "$(code -H "$EDO" -H 'Content-Type: application/json' -d "{\"thumbprint\":\"$TP\",\"data\":\"$ENC\"}" "$API/decrypt")" = 403 ] \
  && pass "система без права decrypt получает 403" || bad "право decrypt не проверяется"

echo "6. Блокировка, смена PIN, аварийная блокировка"
curl -fsS -o /dev/null -X POST -H "$ADM" "$API/keys/$TP/block"
[ "$(code -H "$ERP" -F thumbprint=$TP -F "file=@$OUT/akt.txt" "$API/sign")" = 423 ] && pass "заблокированный ключ: 423" || bad "блокировка"
curl -fsS -o /dev/null -X POST -H "$ADM" "$API/keys/$TP/unblock"
curl -fsS -o /dev/null -X POST -H "$ADM" "$API/keys/$TP/pin/rotate" && pass "плановая смена PIN"
[ "$(save "$OUT/akt.after-rotate.sgn" -H "$ERP" -F thumbprint=$TP -F "file=@$OUT/akt.txt" "$API/sign")" = 200 ] \
  && is_cms "$OUT/akt.after-rotate.sgn" && pass "подпись после смены PIN" || bad "подпись после смены PIN"
curl -fsS -o /dev/null -X POST -H "$ADM" -H 'Content-Type: application/json' -d '{"scope":"all"}' "$API/emergency/block"
[ "$(code -H "$ERP" -F thumbprint=$TP -F "file=@$OUT/akt.txt" "$API/sign")" = 423 ] && pass "аварийная блокировка: 423" || bad "аварийная блокировка"
[ "$(code -X POST -H "$ADM" -H 'Content-Type: application/json' -d '{"scope":"all"}' "$API/emergency/unblock")" = 403 ] \
  && pass "снятие одним администратором запрещено" || bad "снятие без второго администратора"
curl -fsS -o /dev/null -X POST -H "$ADM" -H "X-Approver-Token: $ADM2" -H 'Content-Type: application/json' -d '{"scope":"all"}' "$API/emergency/unblock" \
  && pass "снятие двумя администраторами"

echo "7. Аудит и метрики"
curl -fsS -H "$AUD" "$API/audit?limit=500" > "$OUT/audit.json"
grep -q "\"$PIN\"" "$OUT/audit.json" && bad "PIN найден в аудите!" || pass "PIN в аудите отсутствует"
curl -fsS "$BASE/metrics" > "$OUT/metrics.txt"
grep -q '^esign_operation_seconds_count{op="sign"}' "$OUT/metrics.txt" && pass "метрики /metrics" || bad "метрики"

echo
echo "Итог: $ok успешно, $fail ошибок. Файлы — в $OUT/"
echo "Проверьте подписи $OUT/akt.txt.sig и $OUT/akt.txt.p7m в КриптоПро (cryptcp -verify) или в 1С."
[ "$fail" -eq 0 ]
