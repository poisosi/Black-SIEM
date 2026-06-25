"""
OpenSCAP Writer — runs OVAL scan against host filesystem (mounted at /host),
indexes results into compliance-YYYY.MM.DD. One-shot (restart: no).
"""

import os, subprocess, logging
import xml.etree.ElementTree as ET
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection, helpers
import urllib3
urllib3.disable_warnings()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("oscap-writer")

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

OVAL_DEF   = "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-oval.xml"
RESULT_XML = "/tmp/oscap-results.xml"
TODAY      = datetime.utcnow().strftime("%Y.%m.%d")
TS         = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
IDX        = f"compliance-{TODAY}"
HOSTNAME   = os.uname().nodename


def run_scan() -> bool:
    if not os.path.exists(OVAL_DEF):
        log.warning(f"OVAL definition not found: {OVAL_DEF}")
        return False
    result = subprocess.run(
        ["oscap", "oval", "eval", "--results", RESULT_XML, OVAL_DEF],
        timeout=300, capture_output=True,
    )
    log.info(f"oscap exit={result.returncode}")
    return os.path.exists(RESULT_XML)


def parse_and_index():
    tree = ET.parse(RESULT_XML)
    root = tree.getroot()
    ns   = {"r": "http://oval.mitre.org/XMLSchema/oval-results-5"}
    docs = []
    for result in root.findall(".//r:definition", ns):
        docs.append({"_index": IDX, "_source": {
            "rule_id":    result.get("definition_id", ""),
            "status":     result.get("result", "unknown"),
            "host":       HOSTNAME,
            "@timestamp": TS,
        }})
    if docs:
        ok, _ = helpers.bulk(client, docs, raise_on_error=False)
        log.info(f"Indexed {ok} compliance results → {IDX}")
    else:
        log.warning("No results parsed from XML")


def placeholder():
    client.index(index=IDX, body={
        "rule_id": "scan-skipped", "status": "notapplicable",
        "host": HOSTNAME, "@timestamp": TS,
    })
    log.info(f"Placeholder doc written → {IDX}")


if __name__ == "__main__":
    log.info("OpenSCAP Writer starting …")
    if run_scan():
        parse_and_index()
    else:
        placeholder()
    log.info("Done.")
