"""
CVE Feed Worker — polls NVD API, indexes into cve-YYYY.MM.DD index.
Runs once then sleeps 6h.
"""

import os, time, logging, requests
from datetime import datetime, timedelta
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers
import urllib3
urllib3.disable_warnings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("cve-feed")

_raw   = os.getenv("OPENSEARCH_HOST", "https://localhost:9200").replace("https://","").replace("http://","")
_host, _port = _raw.rsplit(":", 1) if ":" in _raw else (_raw, "9200")
OS_USER = os.getenv("OPENSEARCH_USER", "netbox-svc")
OS_PASS = os.getenv("OPENSEARCH_PASS", "")
NVD_KEY = os.getenv("NVD_API_KEY", "")

client = OpenSearch(
    hosts=[{"host": _host, "port": int(_port)}],
    http_auth=(OS_USER, OS_PASS),
    use_ssl=True, verify_certs=False, ssl_show_warn=False,
    connection_class=RequestsHttpConnection,
)


def fetch_cves(days=1):
    end   = datetime.utcnow()
    start = end - timedelta(days=days)
    fmt   = "%Y-%m-%dT%H:%M:%S.000"
    params = {
        "pubStartDate":   start.strftime(fmt),
        "pubEndDate":     end.strftime(fmt),
        "resultsPerPage": 100,
    }
    headers = {"apiKey": NVD_KEY} if NVD_KEY else {}
    try:
        r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                         params=params, headers=headers, timeout=30)
        r.raise_for_status()
        return r.json().get("vulnerabilities", [])
    except Exception as e:
        log.error(f"NVD fetch error: {e}")
        return []


def index_cves(vulns):
    today = datetime.utcnow().strftime("%Y.%m.%d")
    docs  = []
    for v in vulns:
        cve  = v.get("cve", {})
        cid  = cve.get("id", "")
        desc = (cve.get("descriptions") or [{}])[0].get("value", "")
        cvss, sev = 0.0, "UNKNOWN"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in cve.get("metrics", {}) and cve["metrics"][key]:
                m    = cve["metrics"][key][0].get("cvssData", {})
                cvss = m.get("baseScore", 0.0)
                sev  = m.get("baseSeverity", "UNKNOWN")
                break
        docs.append({"_index": f"cve-{today}", "_source": {
            "cve_id": cid, "description": desc,
            "cvss_score": cvss, "severity": sev,
            "@timestamp": cve.get("published", ""),
        }})
    if docs:
        ok, _ = helpers.bulk(client, docs, raise_on_error=False)
        log.info(f"Indexed {ok}/{len(docs)} CVEs into cve-{today}")


def run():
    while True:
        log.info("Fetching CVEs …")
        vulns = fetch_cves(days=1)
        log.info(f"Got {len(vulns)} entries")
        index_cves(vulns)
        log.info("Sleeping 6h …")
        time.sleep(6 * 3600)


if __name__ == "__main__":
    run()
