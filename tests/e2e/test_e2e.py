"""Сквозные тесты против запущенного сервиса (провайдер openssl-dev, ESIGN_KMS=local).

Запуск:  ESIGN_URL=http://127.0.0.1:8800 pytest -v tests/e2e/test_e2e.py
Нужны тестовые ключи: scripts/make_test_key.sh var/testkeys 12345678 "..." org
и транспортный ключ: scripts/make_test_key.sh var/testkeys 55555555 "esign transport" transport
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
from pathlib import Path

import httpx
import psycopg
import pytest

ROOT = Path(__file__).resolve().parent.parent.parent
URL = os.environ.get("ESIGN_URL", "http://127.0.0.1:8800") + "/api/v1"
KEYS = Path(os.environ.get("ESIGN_TESTKEYS", ROOT / "var" / "testkeys"))
ENV = {**os.environ, "OPENSSL_CONF": str(ROOT / "dev" / "gost.cnf")}
META_DSN = os.environ.get("ESIGN_META_DSN", "postgresql://esign_meta:meta_pw@localhost/esign_meta")
STORE_DSN = os.environ.get("ESIGN_STORE_DSN", "postgresql://esign_store:store_pw@localhost/esign_containers")

ADMIN = {"Authorization": "Bearer admin-token-1"}
ADMIN2 = "admin-token-2"
ERP = {"Authorization": "Bearer erp-token"}
EDO = {"Authorization": "Bearer edo-token"}
AUDIT = {"Authorization": "Bearer audit-token"}
ORG_PIN = "12345678"

c = httpx.Client(base_url=URL, timeout=30)


def ossl(*args, data: bytes | None = None, check=True) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl", *args], input=data, capture_output=True, env=ENV, check=check)


def verify(sig: Path, content: Path | None = None, fmt="DER") -> bool:
    args = ["cms", "-verify", "-binary", "-inform", fmt, "-in", str(sig), "-CAfile", str(KEYS / "ca.crt"),
            "-out", "/dev/null"]
    if content:
        args += ["-content", str(content)]
    return ossl(*args, check=False).returncode == 0


def install(pfx: Path, pin: str, key_type="organization", owner=None, clients=None) -> dict:
    files = {"container": (pfx.name, pfx.read_bytes())}
    data = {"key_type": key_type, "clients": json.dumps(clients or [{"id": "1c-erp", "sign": True, "decrypt": True}])}
    if owner:
        data["owner_login"] = owner
    r = c.post("/keys/uploads", headers=ADMIN, files=files, data=data)
    assert r.status_code == 201, r.text
    upload_id = r.json()["upload_id"]
    r = c.post(f"/keys/uploads/{upload_id}/pin", headers=ADMIN, json={"pin": pin})
    return r


def purge_if_exists(tp: str):
    c.delete(f"/keys/{tp}", params={"purge": "true"}, headers={**ADMIN, "X-Approver-Token": ADMIN2})


def thumb(crt: Path) -> str:
    der = ossl("x509", "-in", str(crt), "-outform", "DER").stdout
    import hashlib
    return hashlib.sha1(der).hexdigest().upper()


@pytest.fixture(scope="module")
def org(tmp_path_factory) -> str:
    tp = thumb(KEYS / "org.crt")
    purge_if_exists(tp)
    r = install(KEYS / "org.pfx", ORG_PIN)
    assert r.status_code == 201, r.text
    assert r.json()["thumbprint"] == tp
    return tp


@pytest.fixture()
def work(tmp_path) -> Path:
    (tmp_path / "doc.bin").write_bytes(os.urandom(200_000))
    (tmp_path / "doc.txt").write_text("Счёт № 15 от 31.10.2026", encoding="utf-8")
    return tmp_path


# ---------------------------------------------------------------- Ф-1
def test_upload_rejects_pin_with_container():
    r = c.post("/keys/uploads", headers=ADMIN, files={"container": ("x.pfx", (KEYS / "org.pfx").read_bytes())},
               data={"pin": ORG_PIN})
    assert r.status_code == 400


def test_upload_wrong_pin_counts_attempts():
    r = c.post("/keys/uploads", headers=ADMIN, files={"container": ("x.pfx", (KEYS / "org.pfx").read_bytes())})
    uid = r.json()["upload_id"]
    for left in (4, 3, 2, 1):
        r = c.post(f"/keys/uploads/{uid}/pin", headers=ADMIN, json={"pin": "bad"})
        assert r.status_code == 422 and str(left) in r.json()["message"]
    r = c.post(f"/keys/uploads/{uid}/pin", headers=ADMIN, json={"pin": "bad"})
    assert r.status_code == 410
    r = c.post(f"/keys/uploads/{uid}/pin", headers=ADMIN, json={"pin": ORG_PIN})
    assert r.status_code == 404


def test_signer_cannot_upload():
    r = c.post("/keys/uploads", headers=ERP, files={"container": ("x.pfx", b"0")})
    assert r.status_code == 403


def test_duplicate(org):
    assert install(KEYS / "org.pfx", ORG_PIN).status_code == 409


def _local_unseal(ct: bytes, wrapped: str, context: str) -> bytes:
    """Снятие шифрования так, как если бы украли и хранилище, и KMS (формат LocalKms)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    keys = json.loads((ROOT / "var" / "kms" / "keys.json").read_text())
    _, ver, body = wrapped.split(":", 2)
    master = base64.b64decode(keys["esign-container"][int(ver[1:]) - 1])
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=context.encode()).derive(master)
    raw = base64.b64decode(body)
    dek = AESGCM(k).decrypt(raw[:12], raw[12:], None)
    return AESGCM(dek).decrypt(ct[:12], ct[12:], context.encode())


def test_pin_replaced_and_storage_dump_useless(org):
    """Ни дамп хранилища, ни исходный PIN не открывают сохранённый ключ."""
    with psycopg.connect(STORE_DSN) as s:
        ct, wrapped = s.execute("SELECT ciphertext, dek_wrapped FROM containers WHERE thumbprint=%s", (org,)).fetchone()
    assert bytes(ct)[:1] != b"\x30" and wrapped.startswith("vault:v")
    pfx = _local_unseal(bytes(ct), wrapped, org)
    assert pfx[:1] == b"\x30"  # под шифрованием — PFX
    r = ossl("pkcs12", "-nodes", "-passin", f"pass:{ORG_PIN}", data=pfx, check=False)
    assert r.returncode != 0, "исходный PIN не должен открывать сохранённую копию"
    with psycopg.connect(META_DSN) as m:
        pin_ct, = m.execute("SELECT pin_ct FROM keys WHERE thumbprint=%s", (org,)).fetchone()
    assert pin_ct.startswith("vault:v") and ORG_PIN not in pin_ct


def test_pin_envelope(tmp_path):
    """PIN шифруется на клиенте транспортным сертификатом сервиса."""
    tp = thumb(KEYS / "emp.crt")
    purge_if_exists(tp)
    cert = c.get("/transport-certificate").content
    (tmp_path / "t.crt").write_bytes(cert)
    env = ossl("cms", "-encrypt", "-binary", "-outform", "DER", "-kuznyechik-ctr-acpkm", str(tmp_path / "t.crt"),
               data=b"87654321").stdout
    r = c.post("/keys/uploads", headers=ADMIN, files={"container": ("emp.pfx", (KEYS / "emp.pfx").read_bytes())},
               data={"key_type": "employee", "owner_login": "ivanov", "clients": "1c-erp"})
    uid = r.json()["upload_id"]
    r = c.post(f"/keys/uploads/{uid}/pin", headers=ADMIN, json={"pin_envelope": base64.b64encode(env).decode()})
    assert r.status_code == 201, r.text
    assert r.json()["key_type"] == "employee"
    # КЭП сотрудника используется сервисом без подтверждения (решение по ТЗ)
    r = c.post("/sign", headers=ERP, json={"thumbprint": tp, "data": base64.b64encode(b"x").decode()})
    assert r.status_code == 200, r.text
    (tmp_path / "x").write_bytes(b"x")
    (tmp_path / "x.sgn").write_bytes(r.content)
    assert verify(tmp_path / "x.sgn", tmp_path / "x")
    purge_if_exists(tp)


# ---------------------------------------------------------------- Ф-2
@pytest.mark.parametrize("ext", ["sgn", "sig", "p7s", "sign"])
def test_sign_file_detached_ext(org, work, ext):
    r = c.post("/sign", headers=ERP, data={"thumbprint": org, "ext": ext},
               files={"file": ("doc.bin", (work / "doc.bin").read_bytes())})
    assert r.status_code == 200, r.text
    assert f"doc.bin.{ext}" in r.headers["content-disposition"]
    (work / f"s.{ext}").write_bytes(r.content)
    assert verify(work / f"s.{ext}", work / "doc.bin")


def test_sign_hash(org, work):
    h = ossl("dgst", "-md_gost12_256", "-binary", str(work / "doc.bin")).stdout
    r = c.post("/sign", headers=ERP, json={"thumbprint": org, "hash": base64.b64encode(h).decode(),
                                           "encoding": "base64"})
    assert r.status_code == 200
    (work / "h.sgn").write_bytes(base64.b64decode(r.content))
    assert verify(work / "h.sgn", work / "doc.bin")


def test_sign_hash_wrong_length(org):
    r = c.post("/sign", headers=ERP, json={"thumbprint": org, "hash": base64.b64encode(b"1" * 20).decode()})
    assert r.status_code == 400 and r.json()["code"] == "bad_hash_length"


def test_sign_attached(org, work):
    r = c.post("/sign", headers=ERP, data={"thumbprint": org, "detached": "false"},
               files={"file": ("doc.txt", (work / "doc.txt").read_bytes())})
    assert r.status_code == 200 and "doc.txt.p7m" in r.headers["content-disposition"]
    (work / "a.p7m").write_bytes(r.content)
    out = ossl("cms", "-verify", "-binary", "-inform", "DER", "-in", str(work / "a.p7m"),
               "-CAfile", str(KEYS / "ca.crt")).stdout
    assert out == (work / "doc.txt").read_bytes()


def test_attached_by_hash_refused(org):
    r = c.post("/sign", headers=ERP, json={"thumbprint": org, "hash": base64.b64encode(b"1" * 32).decode(),
                                           "detached": False})
    assert r.status_code == 400 and r.json()["code"] == "hash_requires_detached"


def test_p7m_only_for_attached(org):
    r = c.post("/sign", headers=ERP, json={"thumbprint": org, "data": "eA==", "ext": "p7m"})
    assert r.status_code == 400


def test_other_system_forbidden(org):
    r = c.post("/sign", headers=EDO, json={"thumbprint": org, "data": "eA=="})
    assert r.status_code == 403


# ---------------------------------------------------------------- Ф-8
def test_encrypt_decrypt_text(org):
    r = c.post("/encrypt", headers=EDO, json={"recipients": [org], "text": "секретная строка", "encoding": "base64"})
    assert r.status_code == 200
    blob = r.content.decode()
    r = c.post("/decrypt", headers=ERP, json={"thumbprint": org, "data": blob, "as_text": True})
    assert r.status_code == 200 and r.json()["text"] == "секретная строка"
    # система без права decrypt
    r = c.post("/decrypt", headers=EDO, json={"thumbprint": org, "data": blob})
    assert r.status_code == 403


def test_encrypt_external_cert_and_magma(org, work):
    cert_pem = (KEYS / "org.crt").read_text()
    r = c.post("/encrypt", headers=EDO, json={"recipient_certs": [cert_pem], "text": "ABC", "cipher": "magma"})
    assert r.status_code == 200
    # расшифровка внешним OpenSSL исходным ключом — совместимость формата
    (work / "e.p7m").write_bytes(r.content)
    out = ossl("cms", "-decrypt", "-inform", "DER", "-in", str(work / "e.p7m"), "-inkey", str(KEYS / "org.key"),
               "-recip", str(KEYS / "org.crt")).stdout
    assert out == b"ABC"


def test_decrypt_file_encrypted_outside(org, work):
    enc = ossl("cms", "-encrypt", "-binary", "-outform", "DER", "-kuznyechik-ctr-acpkm", str(KEYS / "org.crt"),
               data=(work / "doc.bin").read_bytes()).stdout
    r = c.post("/decrypt", headers=ERP, data={"thumbprint": org}, files={"file": ("x.p7m", enc)})
    assert r.status_code == 200 and r.content == (work / "doc.bin").read_bytes()


# ---------------------------------------------------------------- Ф-3, Ф-4, Ф-6
def test_rotate_pin_keeps_signing(org, work):
    r = c.post(f"/keys/{org}/pin/rotate", headers=ADMIN)
    assert r.status_code == 200
    r = c.post("/sign", headers=ERP, data={"thumbprint": org}, files={"file": ("d", (work / "doc.txt").read_bytes())})
    (work / "r.sgn").write_bytes(r.content)
    assert verify(work / "r.sgn", work / "doc.txt")


def test_block_unblock(org):
    assert c.post(f"/keys/{org}/block", headers=ADMIN).json()["status"] == "blocked"
    r = c.post("/sign", headers=ERP, json={"thumbprint": org, "data": "eA=="})
    assert r.status_code == 423 and r.json()["code"] == "key_blocked"
    assert c.post(f"/keys/{org}/unblock", headers=ADMIN).json()["status"] == "active"
    assert c.post("/sign", headers=ERP, json={"thumbprint": org, "data": "eA=="}).status_code == 200


def test_emergency(org):
    assert c.post("/emergency/block", headers=ADMIN, json={"scope": "all"}).status_code == 200
    r = c.post("/sign", headers=ERP, json={"thumbprint": org, "data": "eA=="})
    assert r.status_code == 423 and r.json()["code"] == "emergency_block"
    assert c.post("/emergency/unblock", headers=ADMIN, json={"scope": "all"}).status_code == 403  # без второго
    r = c.post("/emergency/unblock", headers={**ADMIN, "X-Approver-Token": ADMIN2}, json={"scope": "all"})
    assert r.status_code == 200
    assert c.post("/sign", headers=ERP, json={"thumbprint": org, "data": "eA=="}).status_code == 200


def test_audit_has_no_secrets(org):
    rows = c.get("/audit", headers=AUDIT, params={"limit": 1000}).json()
    ops = {r["op"] for r in rows}
    assert {"key.install", "sign", "decrypt"} <= ops
    dump = json.dumps(rows, ensure_ascii=False)
    assert ORG_PIN not in dump and "87654321" not in dump and "секретная строка" not in dump
    assert c.get("/audit", headers=ERP).status_code == 403


def test_delete_restore_purge(org, work):
    r = c.delete(f"/keys/{org}", headers=ADMIN)
    assert r.json()["status"] == "deleted" and r.json()["purge_after"]
    assert c.post("/sign", headers=ERP, json={"thumbprint": org, "data": "eA=="}).json()["code"] == "key_deleted"
    assert c.post(f"/keys/{org}/restore", headers=ADMIN).json()["status"] == "blocked"
    r = c.delete(f"/keys/{org}", params={"purge": "true"}, headers=ADMIN)
    assert r.status_code == 403  # нужен второй администратор
    r = c.delete(f"/keys/{org}", params={"purge": "true"}, headers={**ADMIN, "X-Approver-Token": "admin-token-1"})
    assert r.status_code == 403  # сам себе не подтверждает
    r = c.delete(f"/keys/{org}", params={"purge": "true"}, headers={**ADMIN, "X-Approver-Token": ADMIN2})
    assert r.status_code == 200
    with psycopg.connect(STORE_DSN) as s:
        assert s.execute("SELECT count(*) FROM containers WHERE thumbprint=%s", (org,)).fetchone()[0] == 0
    with psycopg.connect(META_DSN) as m:
        assert m.execute("SELECT pin_ct FROM keys WHERE thumbprint=%s", (org,)).fetchone()[0] is None
    assert c.get(f"/keys/{org}", headers=ADMIN).status_code == 404


def test_metrics(org):
    m = httpx.get(URL.replace("/api/v1", "") + "/metrics").text
    for name in ("esign_http_requests_total", "esign_operation_seconds_bucket", "esign_cache_hits_total",
                 "esign_cache_misses_total", "esign_keys", "esign_keys_expiring_30d", "esign_operations_total"):
        assert name in m, name
    assert 'op="sign"' in m


def test_request_id_in_errors():
    r = c.post("/sign", headers={**ERP, "X-Request-Id": "test-rid-42"}, json={"thumbprint": "00", "data": "eA=="})
    assert r.headers["x-request-id"] == "test-rid-42" and r.json()["request_id"] == "test-rid-42"


def test_unauthenticated():
    assert c.get("/keys").status_code == 401
    assert c.get("/keys", headers={"Authorization": "Bearer nope"}).status_code == 401
