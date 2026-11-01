"""Нагрузочный тест: подпись хэша в N потоков. python3 scripts/load.py <thumbprint> [секунд] [потоков]"""
import base64, os, sys, threading, time, statistics
import httpx
URL = os.environ.get("ESIGN_URL", "http://127.0.0.1:8800") + "/api/v1/sign"
tp, dur, n = sys.argv[1], float(sys.argv[2] if len(sys.argv) > 2 else 10), int(sys.argv[3] if len(sys.argv) > 3 else 16)
lat, errs, stop = [], [], time.time() + dur
def worker():
    c = httpx.Client(timeout=30, headers={"Authorization": "Bearer erp-token"})
    while time.time() < stop:
        t = time.perf_counter()
        r = c.post(URL, json={"thumbprint": tp, "hash": base64.b64encode(os.urandom(32)).decode()})
        (lat if r.status_code == 200 else errs).append(time.perf_counter() - t)
ths = [threading.Thread(target=worker) for _ in range(n)]
[t.start() for t in ths]; [t.join() for t in ths]
lat.sort()
print(f"подписей: {len(lat)}, ошибок: {len(errs)}, {len(lat)/dur:.0f}/с, p50 {statistics.median(lat)*1000:.0f} мс, "
      f"p95 {lat[int(len(lat)*0.95)]*1000:.0f} мс")
