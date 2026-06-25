"""
SIEM+RAG Agent — FastAPI service
  GET  /health   checks all backend services
  POST /query    RAG query (embed → kNN → phi4)
  GET  /alerts   recent Wazuh alerts from OpenSearch
"""

import os
import httpx
import redis as _redis
import urllib3
from fastapi import FastAPI, HTTPException
from opensearchpy import OpenSearch, RequestsHttpConnection
from pydantic import BaseModel

urllib3.disable_warnings()

app = FastAPI(title="SIEM-RAG Agent")

# ── env config ─────────────────────────────────────────────────────────────────
REDIS_HOST   = os.getenv("REDIS_HOST",       "redis")
REDIS_PORT   = int(os.getenv("REDIS_PORT",   "6379"))
REDIS_PASS   = os.getenv("REDIS_PASSWORD",   "")
OLLAMA_HOST  = os.getenv("OLLAMA_HOST",      "http://ollama:11434")
OS_HOST      = os.getenv("OPENSEARCH_HOST",  "https://localhost:9200")
OS_USER      = os.getenv("OPENSEARCH_USER",  "rag-agent-svc")
OS_PASS      = os.getenv("OPENSEARCH_PASS",  "")
WAZUH_URL    = os.getenv("WAZUH_API_URL",    "https://localhost:55000")
NETBOX_URL   = os.getenv("NETBOX_URL",       "http://netbox:8080")
NETBOX_TOKEN = os.getenv("NETBOX_TOKEN",     "")
LLM_MODEL    = os.getenv("LLM_MODEL",        "phi4-reasoning:latest")

# parse OpenSearch URL into host + port
_os_clean  = OS_HOST.replace("https://", "").replace("http://", "")
_os_host, _os_port = _os_clean.rsplit(":", 1) if ":" in _os_clean else (_os_clean, "9200")
_os_scheme = "https" if OS_HOST.startswith("https") else "http"

os_client = OpenSearch(
    hosts=[{"host": _os_host, "port": int(_os_port)}],
    http_auth=(OS_USER, OS_PASS),
    use_ssl=(_os_scheme == "https"),
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False,
    connection_class=RequestsHttpConnection,
)

# ── service health helpers ─────────────────────────────────────────────────────

def _redis_ok() -> bool:
    try:
        r = _redis.Redis(host=REDIS_HOST, port=REDIS_PORT,
                         password=REDIS_PASS, socket_timeout=3)
        return bool(r.ping())
    except Exception:
        return False

def _ollama_ok() -> bool:
    try:
        return httpx.get(f"{OLLAMA_HOST}/api/tags", timeout=5).status_code == 200
    except Exception:
        return False

def _opensearch_ok() -> bool:
    try:
        r = httpx.get(f"{OS_HOST}/", auth=(OS_USER, OS_PASS), verify=False, timeout=5)
        return r.status_code in (200, 401)
    except Exception:
        return False

def _wazuh_ok() -> bool:
    try:
        r = httpx.get(f"{WAZUH_URL}/", verify=False, timeout=5)
        return r.status_code in (200, 401)
    except Exception:
        return False

def _netbox_ok() -> bool:
    try:
        r = httpx.get(f"{NETBOX_URL}/api/", timeout=5,
                      headers={"Authorization": f"Token {NETBOX_TOKEN}"})
        return r.status_code == 200
    except Exception:
        return False

# ── endpoints ──────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    checks = {
        "redis":      _redis_ok(),
        "ollama":     _ollama_ok(),
        "opensearch": _opensearch_ok(),
        "wazuh":      _wazuh_ok(),
        "netbox":     _netbox_ok(),
    }
    stati = {k: ("ok" if v else "error") for k, v in checks.items()}
    stati["status"] = "ok" if all(v for v in checks.values()) else "degraded"
    return stati


class QueryRequest(BaseModel):
    question: str
    top_k: int = 5


@app.post("/query")
def query(req: QueryRequest):
    # 1. embed
    try:
        emb_r = httpx.post(
            f"{OLLAMA_HOST}/api/embeddings",
            json={"model": "nomic-embed-text:v1.5", "prompt": req.question},
            timeout=30,
        )
        embedding = emb_r.json()["embedding"]
    except Exception as e:
        raise HTTPException(500, f"Embedding failed: {e}")

    # 2. k-NN retrieval
    chunks = []
    for idx in ("runbooks-knn", "attack-knn"):
        try:
            res = os_client.search(index=idx, body={
                "size": req.top_k,
                "query": {"knn": {"embedding": {"vector": embedding, "k": req.top_k}}},
                "_source": ["content", "title"],
            })
            for hit in res["hits"]["hits"]:
                s = hit["_source"]
                chunks.append(f"[{s.get('title','?')}]\n{s.get('content','')}")
        except Exception:
            pass

    context = "\n\n".join(chunks) or "No relevant entries found in knowledge base."

    # 3. LLM answer
    prompt = (
        f"You are a SIEM security analyst assistant.\n\n"
        f"Context:\n{context}\n\n"
        f"Question: {req.question}\n\nAnswer:"
    )
    try:
        llm_r = httpx.post(
            f"{OLLAMA_HOST}/api/generate",
            json={"model": LLM_MODEL, "prompt": prompt, "stream": False},
            timeout=600,
        )
        raw = llm_r.json().get("response", "")
    except Exception as e:
        raise HTTPException(500, f"LLM call failed: {e}")

    # phi4-reasoning emits its chain-of-thought wrapped in <think>...</think>.
    # Return only the final answer after the closing tag (graceful if absent).
    answer = raw.split("</think>")[-1].strip() if "</think>" in raw else raw.strip()

    return {
        "question":       req.question,
        "answer":         answer,
        "context_chunks": len(chunks),
    }


@app.get("/alerts")
def alerts(size: int = 20):
    try:
        res = os_client.search(index="wazuh-alerts-*", body={
            "size": size,
            "sort": [{"@timestamp": {"order": "desc"}}],
            "_source": ["@timestamp", "rule.description",
                        "rule.level", "agent.name", "agent.ip"],
        })
        return {"alerts": [h["_source"] for h in res["hits"]["hits"]]}
    except Exception as e:
        return {"alerts": [], "error": str(e)}
