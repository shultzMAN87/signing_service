# Сервис подписания ГОСТ ЭП — тестовая сборка (Rust + КриптоПро CSP)

Сервис по ТЗ «Сервис подписания ГОСТ ЭП»:

* загрузка ключа в два запроса — контейнер и PIN отдельно, PIN можно прислать в конверте;
* смена PIN контейнера на случайный при установке;
* подпись CAdES-BES по файлу и по хэшу, отделённая и прикреплённая
  (`.sgn .sig .p7s .sign .p7m`, DER/Base64/PEM);
* шифрование и расшифровка CMS;
* блокировка, плановая смена PIN, удаление с периодом удержания и уничтожением двумя администраторами;
* аварийная блокировка, аудит, rate limit, метрики Prometheus.

Хранение разнесено: контейнер — в отдельной БД `containers-db`, зашифрован своим
ключом DEK; DEK и PIN зашифрованы в Vault Transit; метаданные и права — в `meta-db`.

## Состав стенда (docker-compose.yml)

| Сервис | Что это |
| --- | --- |
| `meta-db` | PostgreSQL 16: ключи, права систем, зашифрованный PIN, заявки, аудит |
| `containers-db` | PostgreSQL 16: только шифротексты контейнеров |
| `vault` | HashiCorp Vault в режиме dev |
| `vault-init` | включает Transit, создаёт ключи `esign-container` и `esign-pin` (derived), выдаёт сервису токен только на encrypt/decrypt/rewrap |
| `esign` | сам сервис: Rust (axum), КриптоПро CSP 5.0, порт 8800 |

## Быстрый старт

1. Скачайте с cryptopro.ru дистрибутив **КриптоПро CSP 5.0 для Linux x64 (deb)** и
   положите его в `docker/cryptopro/linux-amd64_deb.tgz`. Если имя другое, задайте его
   при сборке: `docker compose build --build-arg CPRO_TGZ=имя.tgz esign`.
2. Лицензия необязательна: без неё действует пробный период. С лицензией —
   `CPRO_SERIAL=XXXXX-... docker compose up`.
3. Запустите стенд:

   ```bash
   docker compose up --build -d
   docker compose logs -f esign     # ждём «HTTP API слушает»
   ```

4. Проверьте сценарий целиком. PFX можно положить в корень проекта, рядом с
   `docker-compose.yml`: в образ он не попадёт (`.dockerignore` исключает `*.pfx`).

   **Windows (PowerShell), через Docker — ничего ставить не нужно:**

   ```powershell
   docker run --rm -it --network signingservice_default -v "${PWD}:/w" -w /w alpine sh -c "apk add -q bash curl && bash scripts/smoke.sh ЭП_Тест_1.pfx 4321 http://esign:8800"
   ```

   * `signingservice_default` — сеть compose. Её имя: имя папки проекта в нижнем
     регистре + `_default`. Точное имя показывает `docker network ls`.
   * В cmd вместо `"${PWD}:/w"` пишите `"%cd%:/w"`.
   * Запуск `./scripts/smoke.sh` прямо из PowerShell не сработает: Windows не
     знает, чем открыть `.sh`. Без WSL-дистрибутива не сработает и `bash ...`.

   **Linux, macOS, WSL, Git Bash:**

   ```bash
   ./scripts/smoke.sh ЭП_Тест_1.pfx 4321
   ```

   Скрипт проходит 22 пункта ТЗ и складывает результаты в `smoke-out/`:

   * `akt.txt` + `akt.txt.sig` / `.sgn` / `.p7s` / `.sign` — отделённые подписи;
   * `akt.txt.p7m` — прикреплённая подпись;
   * `doc.bin.sgn.b64` — подпись файла 300 КБ в Base64;
   * `akt.after-rotate.sgn` — подпись после смены PIN;
   * `audit.json`, `metrics.txt` — аудит и метрики.

   Если ключ уже загружен, на шаге 3 скрипт напишет «ключ уже загружен» и продолжит.

5. Проверьте подписи в «КриптоПро Инструменты» → «Проверить подпись» (или
   `cryptcp -verify`) либо в 1С через менеджер криптографии. Сначала установите
   корневой сертификат тестового УЦ — см. ниже.

## Корневой сертификат тестового УЦ КриптоПро

Тестовые сертификаты выпускает «Тестовый УЦ ООО "КРИПТО-ПРО"». Его корневого
сертификата нет среди доверенных ни в Windows, ни в Linux. Без него проверка
подписи завершится ошибкой, хотя сама подпись верна:

```
Ошибка при проверке (0x800b010a: Не удается построить цепочку сертификатов для доверенного корневого центра.)
```

Корневой сертификат лежит в проекте: `docker/trust/cryptopro-test-ca.pem`.

**Где он нужен:**

| Где | Зачем | Как |
| --- | --- | --- |
| Сервис (`esign`) | проверка цепочки при загрузке ключа | уже подключён: `ESIGN_TRUST_CA=/app/trust/cryptopro-test-ca.pem` в `docker-compose.yml` |
| Компьютер, где проверяют подпись (КриптоПро, 1С) | построение цепочки при проверке | установить в «Доверенные корневые центры сертификации» |

**Установка на Windows** (из папки проекта, PowerShell):

```powershell
certutil -user -addstore Root docker\trust\cryptopro-test-ca.pem
```

Или вручную: скопируйте файл с расширением `.cer` → двойной щелчок →
«Установить сертификат» → «Текущий пользователь» → «Поместить все сертификаты в
следующее хранилище» → «Доверенные корневые центры сертификации» → согласиться
с предупреждением Windows.

**Установка в КриптоПро на Linux:**

```bash
/opt/cprocsp/bin/amd64/certmgr -inst -store uRoot -file docker/trust/cryptopro-test-ca.pem
```

После установки проверка покажет «Подпись успешно проверена» и цепочку
«Тестовый УЦ ООО "КРИПТО-ПРО" → <владелец>». Если КриптоПро предупредит, что не
может проверить отзыв, значит, нет доступа в интернет за CRL тестового УЦ. На
действительность подписи это не влияет.

**Для боевых УЦ** положите их корневые (и промежуточные) сертификаты в PEM в
`docker/trust/` и укажите файл в `ESIGN_TRUST_CA`. Несколько сертификатов можно
склеить в один PEM.

## Токены (docker/clients.json)

| Токен | Система | Роль |
| --- | --- | --- |
| `admin-token-1`, `admin-token-2` | администраторы ключей | `admin` |
| `erp-token` | 1С | `signer` |
| `edo-token` | ЭДО | `signer` |
| `audit-token` | ИБ | `auditor` |

Вызов: `Authorization: Bearer <токен>`. Второй администратор для уничтожения
ключа и снятия аварийной блокировки передаётся в `X-Approver-Token`.

## API (кратко, подробно — раздел 4 ТЗ)

```bash
A="Authorization: Bearer admin-token-1"; S="Authorization: Bearer erp-token"; U=http://localhost:8800/api/v1

# Ф-1: контейнер, затем PIN отдельным запросом
curl -H "$A" -F container=@key.pfx -F key_type=organization \
     -F 'clients=[{"id":"1c-erp","sign":true,"decrypt":true}]' $U/keys/uploads
curl -H "$A" -H 'Content-Type: application/json' -d '{"pin":"1234"}' $U/keys/uploads/<upload_id>/pin

# Ф-2: подпись
curl -H "$S" -F thumbprint=<отпечаток> -F file=@doc.pdf -F ext=sig $U/sign -o doc.pdf.sig        # отделённая
curl -H "$S" -F thumbprint=<отпечаток> -F file=@doc.pdf -F detached=false $U/sign -o doc.pdf.p7m # прикреплённая
curl -H "$S" -H 'Content-Type: application/json' \
     -d '{"thumbprint":"<отпечаток>","hash":"<Base64 ГОСТ Р 34.11-2012>","ext":"p7s"}' $U/sign -o doc.p7s

# Ф-8: шифрование и расшифровка
curl -H "$S" -H 'Content-Type: application/json' -d '{"recipients":["<отпечаток>"],"text":"секрет","encoding":"base64"}' $U/encrypt
curl -H "$S" -H 'Content-Type: application/json' -d '{"thumbprint":"<отпечаток>","data":"<Base64>","as_text":true}' $U/decrypt
```

Остальное: `GET /keys`, `GET /keys/{tp}`, `GET /keys/{tp}/certificate`,
`POST /keys/{tp}/block|unblock|restore|pin/rotate`, `PUT /keys/{tp}/clients`,
`DELETE /keys/{tp}[?purge=true]`, `POST /emergency/block|unblock`, `GET /audit`,
`GET /transport-certificate`, `GET /api/v1/health`, `GET /metrics`.

## Метрики

`GET /metrics` (Prometheus). Если задан `ESIGN_METRICS_TOKEN`, нужен заголовок с этим токеном.

* `esign_http_requests_total{route,status}`
* `esign_operations_total{op,result}` — ошибки по кодам ТЗ
* `esign_operation_seconds{op}` — гистограмма: sign, encrypt, decrypt, install
* `esign_cache_hits_total`, `esign_cache_misses_total`, `esign_cache_entries`
* `esign_keys{status}`, `esign_keys_expiring_30d`

## Настройки (переменные окружения)

| Переменная | По умолчанию | Назначение |
| --- | --- | --- |
| `ESIGN_META_DSN`, `ESIGN_STORE_DSN` | — | две БД |
| `ESIGN_KMS` | `vault` | `vault` или `local` (эмулятор, только для тестов) |
| `VAULT_ADDR`, `VAULT_TOKEN` | — | Vault Transit |
| `ESIGN_PROVIDER` | `cryptopro` | в Docker-образе только `cryptopro` |
| `ESIGN_CRYPTOPRO_LIB` | `/opt/cprocsp/lib/amd64` | каталог libcapi10/20 |
| `ESIGN_CRYPTOPRO_WCHAR` | `4` | размер wchar_t в API КриптоПро на Linux |
| `ESIGN_ENCRYPT_OID` | `1.2.643.2.2.21` | шифр `/encrypt` по умолчанию (ГОСТ 28147-89); «Кузнечик» — `1.2.643.7.1.1.5.2.2` |
| `ESIGN_TRUST_CA` | — | PEM доверенных УЦ; пусто — цепочка не проверяется |
| `ESIGN_TRANSPORT_PFX`, `ESIGN_TRANSPORT_PIN` | — | ключ для `pin_envelope` |
| `ESIGN_TEST_MODE` | `1` | разрешает открытый PIN во втором запросе |
| `ESIGN_RATE_PER_CLIENT`, `ESIGN_RATE_PER_KEY` | `0` | лимит запросов/с (0 — без лимита) |
| `ESIGN_CACHE_MAX`, `ESIGN_CACHE_IDLE_SEC`, `ESIGN_CACHE_TTL_SEC` | 500, 1800, 28800 | кэш открытых ключей |
| `ESIGN_UPLOAD_TTL_MIN`, `ESIGN_PIN_ATTEMPTS`, `ESIGN_RETENTION_DAYS` | 15, 5, 7 | загрузка и удаление |
| `ESIGN_SIGN_EXT`, `ESIGN_ENC_EXT` | `sgn,sig,p7s,sign,p7m`, `p7m,enc` | допустимые расширения |

## Что проверено и что нет

**Проверено в среде разработки (Ubuntu 24.04, 2 vCPU)** — с тестовым провайдером
OpenSSL + gost-engine (`--features openssl-dev`, в Docker-образ не входит):

* 27 сквозных тестов (`tests/e2e`) и `scripts/smoke.sh` (22 пункта) — все проходят.
  Подписи проверяются `openssl cms -verify`, шифрование — расшифровкой внешним OpenSSL.
* Клиент Vault — на заглушке HTTP-API Vault Transit (создание ключа, encrypt и decrypt с context).
* Нагрузка, подпись хэша по HTTP: ~720 подписей/с, p95 9 мс при 4 потоках;
  ~770/с, p95 38 мс при 16 потоках. Память процесса — 17 МБ.

**Проверено на КриптоПро CSP 5.0 (Docker Desktop, Windows, 31.10.2026):**

* Ключ из PFX тестового УЦ ООО «КРИПТО-ПРО» (ГОСТ 2012-256) загружен в два шага,
  PIN заменён сервисом. `scripts/smoke.sh` прошёл все 22 пункта.
* Отделённая подпись `akt.txt.sig` успешно проверена в «КриптоПро Инструменты»:
  CAdES-BES, цепочка до корня тестового УЦ.
* Vault — в режиме dev из `docker-compose.yml`.

**Ещё не проверено:** прикреплённая подпись `.p7m` во внешнем софте, проверка в
1С, нагрузка на КриптоПро (720/с выше — на OpenSSL). Если модуль КриптоПро вернёт
ошибку, её код `0x…` будет в ответе и в логе. Для других сборок КриптоПро может
понадобиться `ESIGN_CRYPTOPRO_WCHAR=2`.

**Не входит в эту сборку (по решению):**

* CRL/OCSP и CAdES-T.
* mTLS — вход по токену.
* Подтверждение операций владельцем КЭП: сотрудник передал ключ, и сервис работает с ним сам.
  Юридические последствия по 63-ФЗ — см. ТЗ.

## Разработка без КриптоПро

```bash
# gost-engine v3.0.3 + dev/gost-engine-acpkm.patch, собранный в /opt/gost-engine/gost.so
cargo build --release --features openssl-dev
./scripts/make_test_key.sh var/testkeys 12345678 "ООО Ромашка (тест)" org
./scripts/make_test_key.sh var/testkeys 87654321 "Иванов Иван (тест)" emp
./scripts/make_test_key.sh var/testkeys 55555555 "esign transport" transport
ESIGN_PROVIDER=openssl-dev ESIGN_OPENSSL_CONF=$PWD/dev/gost.cnf ESIGN_CLIENTS_FILE=dev/clients.json ESIGN_KMS=local \
ESIGN_TRUST_CA=var/testkeys/ca.crt ESIGN_TRANSPORT_PFX=var/testkeys/transport.pfx ESIGN_TRANSPORT_PIN=55555555 \
  ./target/release/esign
pytest -q tests/e2e/test_e2e.py
```

## Безопасность (что сделано в коде)

* PIN и расшифрованный контейнер хранятся в `Zeroizing`-буферах и затираются после использования.
* Временные контейнеры КриптоПро лежат в tmpfs (`/var/opt/cprocsp/keys/esign`) и
  удаляются при вытеснении ключа из кэша и при старте сервиса.
* Шифротекст контейнера привязан к отпечатку (AAD), DEK и PIN — к отпечатку как
  context Vault. Подменить запись одного ключа записью другого нельзя.
* У сервиса токен Vault только на encrypt/decrypt/rewrap.
* PIN, ключи и содержимое документов не пишутся в логи и аудит; в аудите — хэш документа.
* Аудит в БД только на добавление (триггер запрещает UPDATE и DELETE).
