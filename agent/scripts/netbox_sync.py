"""
NetBox Sync Worker — pulls device inventory from NetBox, writes to
netbox-sync and asset-id-lookup indices. Runs once then sleeps 30m.
"""

import os, time, logging, requests
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers
import urllib3
urllib3.disable_warnings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("netbox-sync")

NETBOX_URL   = os.getenv("NETBOX_URL",   "http://netbox:8080")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN", "")
_raw   = os.getenv("OPENSEARCH_HOST", "https://localhost:9200").replace("https://","").replace("http://","")
_host, _port = _raw.rsplit(":", 1) if ":" in _raw else (_raw, "9200")
OS_USER = os.getenv("OPENSEARCH_USER", "netbox-svc")
OS_PASS = os.getenv("OPENSEARCH_PASS", "")

client = OpenSearch(
    hosts=[{"host": _host, "port": int(_port)}],
    http_auth=(OS_USER, OS_PASS),
    use_ssl=True, verify_certs=False, ssl_show_warn=False,
    connection_class=RequestsHttpConnection,
)

NB_HDR = {"Authorization": f"Token {NETBOX_TOKEN}",
           "Content-Type":  "application/json"}


def fetch_devices():
    try:
        r = requests.get(f"{NETBOX_URL}/api/dcim/devices/?limit=1000",
                         headers=NB_HDR, timeout=15)
        r.raise_for_status()
        return r.json().get("results", [])
    except Exception as e:
        log.error(f"NetBox fetch error: {e}")
        return []


def sync():
    devices = fetch_devices()
    log.info(f"Fetched {len(devices)} devices")
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    sync_docs, lookup_docs = [], []

    for d in devices:
        did  = str(d.get("id", ""))
        name = d.get("name", "")
        ip   = (d.get("primary_ip") or {}).get("address", "").split("/")[0]
        site = (d.get("site") or {}).get("name", "")

        sync_docs.append({"_index": "netbox-sync", "_id": did, "_source": {
            "asset_id": did, "hostname": name,
            "ip": ip or None, "site": site, "@timestamp": ts,
        }})
        lookup_docs.append({"_index": "asset-id-lookup", "_id": did, "_source": {
            "asset_id": did,
            "netbox_url": f"{NETBOX_URL}/dcim/devices/{did}/",
            "@timestamp": ts,
        }})

    for docs in (sync_docs, lookup_docs):
        if docs:
            ok, _ = helpers.bulk(client, docs, raise_on_error=False)
            log.info(f"Indexed {ok} docs → {docs[0]['_index']}")


def run():
    while True:
        sync()
        log.info("Sleeping 30m …")
        time.sleep(1800)


if __name__ == "__main__":
    run()
