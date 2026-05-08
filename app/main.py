import os
import json
import asyncio
import subprocess
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import websockets
from clickhouse_driver import Client

APP_PORT = int(os.getenv("APP_PORT", 8080))
CH_HOST = os.getenv("CH_HOST", "localhost")
CH_PORT = int(os.getenv("CH_PORT", 9000))
CH_USER = os.getenv("CH_USER", "default")
CH_PASSWORD = os.getenv("CH_PASSWORD", "")
CH_DATABASE = os.getenv("CH_DATABASE", "ct_browser")
WS_URL = os.getenv("WS_URL", "ws://certstream:8080/")

# in-memory buffer for batch inserts
buffer: list[tuple] = []
BUFFER_SIZE = 5000
buffer_lock = asyncio.Lock()
templates = Jinja2Templates(directory=".")


def get_version() -> str:
    try:
        return (
            subprocess.check_output(["git", "describe", "--tags", "--always"])
            .decode("utf-8")
            .strip()
        )
    except Exception:
        return "DEV_BUILD"


def get_ch_client() -> Client:
    return Client(
        host=CH_HOST,
        port=CH_PORT,
        user=CH_USER,
        password=CH_PASSWORD,
        database=CH_DATABASE,
        settings={"insert_block_size": BUFFER_SIZE},
    )


async def flush_buffer():
    """flush buffered records to clickhouse"""
    global buffer
    async with buffer_lock:
        if not buffer:
            return
        data_to_insert = buffer.copy()
        buffer.clear()

    try:
        client = get_ch_client()
        client.execute(
            """
            INSERT INTO cert_events 
            (cert_id, common_name, issuer_o, serial_number, update_type, log_name, sig_alg, cert_link, first_seen, last_seen, emitted_at, expires_at)
            VALUES
            """,
            data_to_insert,
        )
        print(f"flushed {len(data_to_insert)} records to ch")
    except Exception as e:
        print(f"ch insert error: {e}")
        async with buffer_lock:
            if len(buffer) + len(data_to_insert) < BUFFER_SIZE * 2:
                buffer.extend(data_to_insert)
    finally:
        try:
            client.disconnect()
        except:
            pass


def _ensure_utc(dt: Optional[datetime]) -> Optional[datetime]:
    """ensure a datetime is utc aware"""
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


async def ingest_ws():
    """async websocket consumer for certstream lite stream"""
    print(f"connecting to ct ws at {WS_URL}...")
    retry_delay = 1.0
    max_retry_delay = 60.0

    while True:
        try:
            async with websockets.connect(WS_URL) as websocket:
                print("connected to ct ws! streaming...")
                retry_delay = 1.0

                async for message in websocket:
                    try:
                        msg = json.loads(message)
                    except json.JSONDecodeError:
                        continue

                    if msg.get("message_type") != "certificate_update":
                        continue

                    data_payload = msg.get("data", {})
                    leaf_cert = data_payload.get("leaf_cert", {})
                    domains = leaf_cert.get("all_domains", [])
                    if not domains:
                        continue

                    cert_id = leaf_cert.get("sha256") or leaf_cert.get(
                        "fingerprint", ""
                    )
                    if not cert_id:
                        continue

                    issuer_o = leaf_cert.get("issuer", {}).get("O", "UNKNOWN_CA")
                    serial = leaf_cert.get("serial_number", "UNKNOWN_SERIAL")
                    update_type = data_payload.get("update_type", "UNKNOWN_TYPE")
                    log_name = data_payload.get("source", {}).get("name", "UNKNOWN_LOG")
                    sig_alg = leaf_cert.get("signature_algorithm", "UNKNOWN_ALG")
                    cert_link = data_payload.get("cert_link", "")

                    not_before = leaf_cert.get("not_before")
                    not_after = leaf_cert.get("not_after")
                    emitted_at = (
                        datetime.fromtimestamp(not_before, tz=timezone.utc)
                        if not_before
                        else None
                    )
                    expires_at = (
                        datetime.fromtimestamp(not_after, tz=timezone.utc)
                        if not_after
                        else None
                    )
                    now = datetime.now(timezone.utc)

                    for domain in domains:
                        if not domain or not isinstance(domain, str):
                            continue

                        record = (
                            cert_id,
                            domain,
                            issuer_o,
                            serial,
                            update_type,
                            log_name,
                            sig_alg,
                            cert_link,
                            now,
                            now,
                            emitted_at,
                            expires_at,
                        )

                        async with buffer_lock:
                            buffer.append(record)

                        if len(buffer) >= BUFFER_SIZE:
                            await flush_buffer()

        except Exception as e:
            print(f"ws error: {e} - retry in {retry_delay:.1f}s...")
        finally:
            await flush_buffer()
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 1.5, max_retry_delay)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(ingest_ws())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass


app = FastAPI(lifespan=lifespan, title="CT Browser")


@app.get("/", response_class=HTMLResponse)
async def index(request: Request, q: str = "", p: int = 1):
    """SSR index page with deep forensics"""
    limit = 50
    offset = (p - 1) * limit
    results = []
    error = None

    top_issuers = []
    total_stats = -1

    client = None
    try:
        client = get_ch_client()

        # top 5 issuers for the header
        issuer_stats_query = "SELECT issuer_o, count() as cnt FROM cert_events FINAL GROUP BY issuer_o ORDER BY cnt DESC LIMIT 5"
        top_issuers = client.execute(issuer_stats_query)

        total_stats_query = "SELECT count() as cnt FROM cert_events FINAL"
        total_stats = client.execute(total_stats_query)

        if q.strip():
            query = """
                SELECT cert_id, common_name, issuer_o, serial_number, update_type, log_name, sig_alg, cert_link, first_seen, last_seen, emitted_at, expires_at
                FROM cert_events FINAL
                WHERE match(common_name, %(regex_q)s)
                ORDER BY last_seen DESC
                LIMIT %(limit)s OFFSET %(offset)s
            """

            params = {"regex_q": q, "limit": limit, "offset": offset}
            rows = client.execute(query, params)
            results = [
                {
                    "cert_id": r[0],
                    "common_name": r[1],
                    "issuer_o": r[2],
                    "serial_number": r[3],
                    "update_type": r[4],
                    "log_name": r[5],
                    "sig_alg": r[6],
                    "cert_link": r[7],
                    "first_seen": _ensure_utc(r[8]),
                    "last_seen": _ensure_utc(r[9]),
                    "emitted_at": _ensure_utc(r[10]),
                    "expires_at": _ensure_utc(r[11]),
                }
                for r in rows
            ]
    except Exception as e:
        error = str(e)
    finally:
        if client:
            try:
                client.disconnect()
            except:
                pass

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "results": results,
            "top_issuers": top_issuers,
            "total_stats": total_stats,
            "q": q,
            "p": p,
            "error": error,
            "buffer_size": len(buffer),
            "buffer_max_size": BUFFER_SIZE,
            "now": datetime.now(timezone.utc),
            "version": get_version(),
        },
    )


@app.get("/health")
async def health_check():
    return {"status": "healthy", "buffer_size": len(buffer)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=APP_PORT, log_level="info")
