#!/bin/bash
# install_grafana.sh — single-command installer: Wazuh + NetBox + Grafana + RAG platform
#
# This script replaces install.sh. Do NOT run both.
# Grafana is included from the start as the unified data-correlation dashboard.
#
# Usage:
#   bash install_grafana.sh https://github.com/YOUR-USER/rag-security-platform.git
# Or via env var:
#   REPO_URL=https://github.com/YOUR-USER/rag-security-platform.git bash install_grafana.sh
# Or inspect first:
#   curl -o install_grafana.sh <URL>
#   less install_grafana.sh
#   bash install_grafana.sh https://github.com/YOUR-USER/rag-security-platform.git
#
# DESIGN NOTE: intentionally plain. Checks things, proceeds or tells you
# exactly what to run yourself. NetBox SECRET_KEY is the one auto-generated
# value (via openssl). Docker auto-install uses sudo internally (get.docker.com
# standard pattern) — all other sudo operations are left to you.

set -e

# ============================================================
# SECTION 1 — CREDENTIALS & CONFIG
# ============================================================

PASS="SIEMlab@4321"

# PASS_URLENC: encodes "@" → "%40" for use in connection string URLs.
# Only "@" is encoded — the one character in PASS that breaks user:pass@host parsing.
PASS_URLENC="${PASS//@/%40}"

# Guard: fail loudly if PASS ever changes to include a character this script
# does not encode, rather than producing a silently broken connection string.
if [[ "$PASS" == *[:/\#\%[:space:]]* ]]; then
  echo "ERROR: PASS contains a character (:, /, #, %, or whitespace) that PASS_URLENC does not"
  echo "  encode. Update the PASS_URLENC substitution above, or change PASS to avoid it."
  exit 1
fi

# Accept REPO_URL from: first CLI argument, env var set before calling the script,
# or leave empty to get a clear error below.
REPO_URL="${1:-${REPO_URL:-}}"

# Guard: fail immediately if REPO_URL was not provided.
if [[ -z "$REPO_URL" ]]; then
  echo "ERROR: REPO_URL not set."
  echo "  Pass your repo URL as the first argument:"
  echo "    bash install_grafana.sh https://github.com/YOUR-USER/rag-security-platform.git"
  echo "  Or export it before running:"
  echo "    REPO_URL=https://github.com/YOUR-USER/rag-security-platform.git bash install_grafana.sh"
  exit 1
fi
WAZUH_TAG="v4.14.5"
INSTALL_DIR="${INSTALL_DIR:-$HOME/rag-security-platform}"

# Ports — host:container
# wazuh.indexer occupies host port 9200 (its own compose).
# Plain OpenSearch is on 9201 to avoid that conflict.
# Grafana is on 3001 — chat-ui occupies 3000.
PORT_OPENSEARCH="9201:9200"
PORT_POSTGRES="5432:5432"
PORT_NETBOX="8000:8080"
PORT_OLLAMA="11434:11434"
PORT_AGENT="8080:8080"
PORT_CHATUI="3000:3000"
PORT_GRAFANA="3001:3000"

# Grafana — pin to current stable, never use :latest.
# grafana-opensearch-datasource (2.33.1) requires >=10.4.0 — Grafana 13 is supported.
# NOTE: Grafana 12+ uses GF_PLUGINS_PREINSTALL (not GF_INSTALL_PLUGINS).
# If you bump this beyond 13.x, verify the plugin dep range still covers it.
GRAFANA_VERSION="13.0.2"

# OpenSearch version strings — Grafana datasource plugin uses these
# to pick the correct query dialect. These are NOT the same value:
#   wazuh.indexer (wazuh-docker 4.14.5) ships OpenSearch 2.19.5
#   plain opensearch service is opensearchproject/opensearch:3.7.0
WAZUH_OPENSEARCH_VERSION="2.19.5"
PLAIN_OPENSEARCH_VERSION="3.7.0"

# ============================================================
# SECTION 2 — DOCKER & PREREQUISITES
# ============================================================
echo "→ Checking prerequisites..."

if ! command -v docker >/dev/null 2>&1; then
  echo "→ Docker not found. Installing via get.docker.com (requires sudo)..."
  if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl is not installed. Install it first: sudo apt-get install -y curl"
    exit 1
  fi
  curl -fsSL https://get.docker.com | sh
  sudo usermod -aG docker "$USER"
  sudo systemctl enable --now docker
  echo ""
  echo "✓ Docker installed."
  echo ""
  echo "  Your user has been added to the 'docker' group, but this only takes"
  echo "  effect after a fresh login. Log out now, log back in, then re-run:"
  echo ""
  echo "    bash install_grafana.sh"
  echo ""
  exit 0
fi

if ! docker info >/dev/null 2>&1; then
  if sudo docker info >/dev/null 2>&1; then
    echo "ERROR: Docker is running but your user cannot reach it."
    echo "  Your user may not be in the 'docker' group yet."
    echo "  Fix: sudo usermod -aG docker \$USER  then log out and back in."
  else
    echo "ERROR: Docker daemon is not running."
    echo "  Fix: sudo systemctl start docker"
  fi
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: Docker Compose plugin not found."
  echo "  get.docker.com installs it automatically. If you installed Docker"
  echo "  another way, add the plugin: https://docs.docker.com/compose/install/linux/"
  exit 1
fi

if ! command -v git >/dev/null 2>&1; then
  echo "→ git not found. Installing..."
  sudo apt-get update -qq
  sudo apt-get install -y git
fi

if ! command -v openssl >/dev/null 2>&1; then
  echo "ERROR: openssl is not installed (required to generate NetBox SECRET_KEY)."
  echo "  Fix: sudo apt-get install -y openssl"
  exit 1
fi
echo "✓ Docker, git, and openssl found."

# Generate NetBox Django SECRET_KEY — 45 random bytes, base64-encoded (~60 chars).
# A-Za-z0-9+/= are all valid for Django SECRET_KEY and safe as a YAML plain string.
SECRET_KEY=$(openssl rand -base64 45 | tr -d '\n')

if [ "$(uname)" = "Linux" ]; then
  MAP_COUNT=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
  if [ "$MAP_COUNT" -lt 262144 ]; then
    echo "ERROR: vm.max_map_count is ${MAP_COUNT} — OpenSearch requires at least 262144."
    echo "Run these yourself, then re-run this installer:"
    echo "  sudo sysctl -w vm.max_map_count=262144"
    echo "  echo 'vm.max_map_count=262144' | sudo tee -a /etc/sysctl.conf"
    exit 1
  fi
  echo "✓ vm.max_map_count=${MAP_COUNT} (OK)."
else
  echo "→ Non-Linux host — vm.max_map_count check skipped (Docker Desktop handles this)."
fi

# ============================================================
# SECTION 3 — CLONE
# ============================================================
echo "→ Cloning repos..."

if [ -d "$INSTALL_DIR" ]; then
  echo "ERROR: ${INSTALL_DIR} already exists. Remove it first for a fresh install:"
  echo "  rm -rf ${INSTALL_DIR}"
  echo "If a previous run created the Docker network or containers, clean those up too:"
  echo "  docker network rm rag-platform 2>/dev/null"
  echo "  docker ps -a --filter network=rag-platform -q | xargs -r docker rm -f"
  exit 1
fi

if ! git clone "$REPO_URL" "$INSTALL_DIR"; then
  echo "ERROR: could not clone ${REPO_URL}. Check your internet connection."
  exit 1
fi
cd "$INSTALL_DIR"

mkdir -p wazuh

# Pin to a stable release tag — wazuh-docker main currently tracks an unreleased
# 5.0.0-beta line with broken cert-tool URLs. Never clone bare main.
if ! git clone --branch "$WAZUH_TAG" https://github.com/wazuh/wazuh-docker.git wazuh/wazuh-docker; then
  echo "ERROR: could not clone wazuh-docker at tag ${WAZUH_TAG}."
  exit 1
fi

if [ ! -d agent ] || [ ! -d chat-ui ]; then
  echo "ERROR: repo is missing the 'agent' and/or 'chat-ui' directories."
  echo "This script does not write application code — add those directories"
  echo "(see BUILD_STEPS.md) before running this installer."
  exit 1
fi

# ============================================================
# SECTION 4 — DOCKER COMPOSE
# One file, services organised by component.
# Wazuh is NOT here — it runs from its own compose in
# wazuh/wazuh-docker/single-node/. It joins this stack's network
# via the override file written in Section 7.
# ============================================================
echo "→ Writing docker-compose.yml..."

cat > docker-compose.yml <<COMPOSE_EOF
networks:
  default:
    name: rag-platform
    external: true

services:

  # ── OpenSearch (non-Wazuh log sources) ───────────────────
  # Plain, no auth. Wazuh has its own indexer on host port 9200.
  # This instance is for other log sources — host port 9201.
  opensearch:
    image: opensearchproject/opensearch:3.7.0
    restart: unless-stopped
    environment:
      - discovery.type=single-node
      - DISABLE_SECURITY_PLUGIN=true
      - OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g
    healthcheck:
      test: ["CMD-SHELL", "curl -sf http://localhost:9200/_cluster/health || exit 1"]
      start_period: 60s
      interval: 15s
      timeout: 5s
      retries: 10
    volumes:
      - opensearch-data:/usr/share/opensearch/data
    ports:
      - "${PORT_OPENSEARCH}"

  # ── PostgreSQL ───────────────────────────────────────────
  postgres:
    image: postgres:18.4-alpine
    restart: unless-stopped
    environment:
      - POSTGRES_DB=netbox
      - POSTGRES_USER=netbox
      - POSTGRES_PASSWORD=${PASS}
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U netbox"]
      start_period: 10s
      interval: 10s
      timeout: 5s
      retries: 5
    volumes:
      - postgres-data:/var/lib/postgresql/data
    ports:
      - "${PORT_POSTGRES}"

  # ── NetBox & prerequisites ───────────────────────────────
  # Two Valkey instances required by NetBox: task queue + cache.
  redis:
    image: valkey/valkey:9.0-alpine
    restart: unless-stopped
    command: ["valkey-server", "--requirepass", "${PASS}"]

  redis-cache:
    image: valkey/valkey:9.0-alpine
    restart: unless-stopped
    command: ["valkey-server", "--requirepass", "${PASS}"]

  netbox:
    image: netboxcommunity/netbox:v4.6.2
    restart: unless-stopped
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_started
      redis-cache:
        condition: service_started
    environment:
      - DB_HOST=postgres
      - DB_NAME=netbox
      - DB_USER=netbox
      - DB_PASSWORD=${PASS}
      - REDIS_HOST=redis
      - REDIS_PASSWORD=${PASS}
      - REDIS_CACHE_HOST=redis-cache
      - REDIS_CACHE_PASSWORD=${PASS}
      - SUPERUSER_PASSWORD=${PASS}
      - SKIP_SUPERUSER=false
      - SECRET_KEY=${SECRET_KEY}
    healthcheck:
      test: ["CMD-SHELL", "curl -f http://localhost:8080/login/ || exit 1"]
      start_period: 90s
      interval: 15s
      timeout: 3s
      retries: 5
    ports:
      - "${PORT_NETBOX}"

  # ── Grafana ──────────────────────────────────────────────
  # Unified data-correlation dashboard — queries all sources.
  # Datasources provisioned via grafana-provisioning/ (written in Section 8).
  # grafana-opensearch-datasource plugin installed at first container start.
  grafana:
    image: grafana/grafana:${GRAFANA_VERSION}
    restart: unless-stopped
    depends_on:
      opensearch:
        condition: service_healthy
      postgres:
        condition: service_healthy
    environment:
      - GF_SECURITY_ADMIN_USER=admin
      - GF_SECURITY_ADMIN_PASSWORD=${PASS}
      - GF_PATHS_PROVISIONING=/etc/grafana/provisioning
      - GF_PLUGINS_PREINSTALL=grafana-opensearch-datasource
      - GF_PANELS_DISABLE_SANITIZE_HTML=true
    volumes:
      - grafana-data:/var/lib/grafana
      - ./grafana-provisioning:/etc/grafana/provisioning:ro
    healthcheck:
      test: ["CMD-SHELL", "wget -q -O /dev/null http://localhost:3000/api/health || exit 1"]
      start_period: 60s
      interval: 15s
      timeout: 5s
      retries: 8
    ports:
      - "${PORT_GRAFANA}"

  # ── Ollama (LLM runtime) ─────────────────────────────────
  ollama:
    image: ollama/ollama:0.30.10
    restart: unless-stopped
    volumes:
      - ollama-data:/root/.ollama
    ports:
      - "${PORT_OLLAMA}"

  # ── RAG Agent ────────────────────────────────────────────
  # Queries all sources and synthesises answers via LLM.
  # Sources: wazuh.indexer, opensearch, postgres (NetBox), redis-cache, ollama.
  # wazuh.indexer is reached over HTTPS with TLS verification OFF — same
  # approach as Grafana's datasource. No CA cert mount (kept simple/consistent).
  agent:
    build: ./agent
    restart: unless-stopped
    depends_on:
      opensearch:
        condition: service_healthy
      postgres:
        condition: service_healthy
      netbox:
        condition: service_healthy
    environment:
      - OPENSEARCH_URL=http://opensearch:9200
      - NETBOX_DB_URL=postgresql://netbox:${PASS_URLENC}@postgres:5432/netbox
      - CHAT_REDIS_URL=redis://:${PASS_URLENC}@redis-cache:6379/0
      - CHAT_REDIS_KEY_PREFIX=chat:
      - OLLAMA_URL=http://ollama:11434
      - WAZUH_INDEXER_URL=https://wazuh.indexer:9200
      - WAZUH_INDEXER_USER=admin
      - WAZUH_INDEXER_PASSWORD=SecretPassword
      - WAZUH_INDEXER_VERIFY=false
    ports:
      - "${PORT_AGENT}"

  # ── Chat UI ──────────────────────────────────────────────
  chat-ui:
    build: ./chat-ui
    restart: unless-stopped
    depends_on: [agent]
    environment:
      - AGENT_URL=http://agent:8080
    ports:
      - "${PORT_CHATUI}"

volumes:
  postgres-data:
  grafana-data:
  ollama-data:
  opensearch-data:
COMPOSE_EOF

echo "✓ docker-compose.yml written."

# ============================================================
# SECTION 5 — INTERCOM (Docker network)
# Shared network that connects every component.
# Wazuh joins this via the override file in Section 7.
# ============================================================
echo "→ Creating shared Docker network..."
if ! docker network inspect rag-platform >/dev/null 2>&1; then
  if ! docker network create rag-platform; then
    echo "ERROR: could not create Docker network 'rag-platform'. Is the Docker daemon running?"
    exit 1
  fi
fi
echo "✓ Network rag-platform ready."

# ============================================================
# SECTION 6 — CERTS
# Wazuh certificates must be generated before any Wazuh container
# starts — the indexer, manager, and dashboard use them for their
# own internal TLS. Nothing outside the Wazuh stack consumes these:
# the agent and Grafana both reach wazuh.indexer with TLS verify off.
# ============================================================
echo "→ Generating Wazuh certificates..."
cd wazuh/wazuh-docker/single-node
if ! docker compose -f generate-indexer-certs.yml run --rm generator; then
  echo "ERROR: certificate generation failed. Check:"
  echo "  cd $(pwd) && docker compose -f generate-indexer-certs.yml logs"
  exit 1
fi
echo "✓ Certificates generated."

# ============================================================
# SECTION 7 — WAZUH CONFIG
# Override file attaches Wazuh's own compose stack to rag-platform
# so wazuh.indexer is reachable by the agent and Grafana as
# https://wazuh.indexer:9200 from within the same network.
# ============================================================
cat > docker-compose.override.yml <<WAZUH_EOF
networks:
  default:
    name: rag-platform
    external: true
WAZUH_EOF
echo "✓ Wazuh network override written."

echo
echo "NOTE — Wazuh has THREE separate credentials, all its own defaults."
echo "This script does not touch any of them:"
echo "  admin / SecretPassword      — indexer login (bcrypt hash in internal_users.yml)"
echo "  kibanaserver / kibanaserver — dashboard↔indexer internal account"
echo "  wazuh-wui / MyS3cr37P450r.*- — manager REST API (env var, must match on both sides)"
echo "To change them: https://documentation.wazuh.com/current/deployment-options/docker/changing-default-password.html"
echo

# ============================================================
# SECTION 8 — GRAFANA CONFIG
# Datasource provisioning — written after cert gen so Section 6
# has already confirmed the Wazuh stack is ready to be connected.
# Wazuh indexer uses tlsSkipVerify — no inline cert, clean and
# consistent with lab philosophy. Agent also uses TLS verify off (WAZUH_INDEXER_VERIFY=false).
# ============================================================
cd "$INSTALL_DIR"
echo "→ Writing Grafana datasource provisioning..."
mkdir -p grafana-provisioning/datasources

cat > grafana-provisioning/datasources/datasources.yml <<DS_EOF
apiVersion: 1

datasources:

  - name: Wazuh Indexer
    uid: wazuh-indexer
    type: grafana-opensearch-datasource
    access: proxy
    url: https://wazuh.indexer:9200
    basicAuth: true
    basicAuthUser: admin
    jsonData:
      database: "wazuh-alerts-4.x-*"
      timeField: "timestamp"
      flavor: opensearch
      version: "${WAZUH_OPENSEARCH_VERSION}"
      tlsSkipVerify: true
      logMessageField: "rule.description"
      logLevelField: "rule.level"
    secureJsonData:
      basicAuthPassword: SecretPassword
    isDefault: false
    editable: true

  - name: OpenSearch (logs)
    uid: opensearch-logs
    type: grafana-opensearch-datasource
    access: proxy
    url: http://opensearch:9200
    jsonData:
      database: "*"
      timeField: "@timestamp"
      flavor: opensearch
      version: "${PLAIN_OPENSEARCH_VERSION}"
    isDefault: false
    editable: true

  - name: NetBox (PostgreSQL)
    uid: netbox-postgres
    type: postgres
    access: proxy
    url: postgres:5432
    user: netbox
    secureJsonData:
      password: "${PASS}"
    jsonData:
      database: netbox
      sslmode: disable
      postgresVersion: 1800
    isDefault: false
    editable: true
DS_EOF

echo "✓ Grafana datasource provisioning written."

# ============================================================
# SECTION 9 — GRAFANA DASHBOARD PROVISIONING
# dashboards.yml tells Grafana which folder to scan for JSON files.
# unified.json is the pre-built Security Operations dashboard:
#   - Stat panels: total alerts, critical alerts
#   - Table: top 10 source IPs (terms agg on Wazuh)
#   - Timeseries: alert timeline
#   - Table: NetBox asset inventory joined with Wazuh alert count
#              (joined on agent.name = NetBox device hostname)
#   - Logs: last 50 raw Wazuh alerts
#   - Text/HTML iframe: RAG chat-ui embedded in right sidebar
# ============================================================
echo "→ Writing Grafana dashboard provisioning..."
mkdir -p grafana-provisioning/dashboards

cat > grafana-provisioning/dashboards/dashboards.yml <<'DASHPROV_EOF'
apiVersion: 1

providers:
  - name: default
    type: file
    disableDeletion: false
    updateIntervalSeconds: 30
    allowUiUpdates: true
    options:
      path: /etc/grafana/provisioning/dashboards
DASHPROV_EOF

# Single-quoted heredoc — Grafana variables like ${chat_ui_url} must
# reach the JSON file unexpanded; bash must not interpret them.
cat > grafana-provisioning/dashboards/unified.json <<'DASH_EOF'
{
  "title": "Security Operations — Unified",
  "uid": "soc-unified-v1",
  "version": 1,
  "schemaVersion": 42,
  "refresh": "30s",
  "time": { "from": "now-24h", "to": "now" },
  "timepicker": {
    "refresh_intervals": ["10s","30s","1m","5m","15m","30m","1h","2h","1d"],
    "time_options": ["5m","15m","1h","6h","12h","24h","2d","7d","30d"]
  },
  "templating": {
    "list": [
      {
        "name": "chat_ui_url",
        "label": "Chat UI URL",
        "type": "textbox",
        "current": {
          "selected": false,
          "text": "http://localhost:3000",
          "value": "http://localhost:3000"
        },
        "options": [
          {
            "selected": false,
            "text": "http://localhost:3000",
            "value": "http://localhost:3000"
          }
        ],
        "query": "http://localhost:3000",
        "hide": 0,
        "skipUrlSync": false
      }
    ]
  },
  "panels": [

    {
      "id": 1,
      "title": "Total Alerts",
      "type": "stat",
      "gridPos": { "x": 0, "y": 0, "w": 6, "h": 4 },
      "datasource": { "type": "grafana-opensearch-datasource", "uid": "wazuh-indexer" },
      "targets": [
        {
          "refId": "A",
          "query": "*",
          "timeField": "timestamp",
          "metrics": [{ "id": "1", "type": "count" }],
          "bucketAggs": []
        }
      ],
      "options": {
        "colorMode": "background",
        "graphMode": "none",
        "justifyMode": "center",
        "textMode": "auto",
        "reduceOptions": { "calcs": ["sum"], "fields": "", "values": false }
      },
      "fieldConfig": {
        "defaults": {
          "color": { "mode": "thresholds" },
          "thresholds": {
            "mode": "absolute",
            "steps": [
              { "color": "green", "value": null },
              { "color": "yellow", "value": 100 },
              { "color": "red", "value": 500 }
            ]
          },
          "unit": "short",
          "mappings": []
        },
        "overrides": []
      }
    },

    {
      "id": 2,
      "title": "Critical Alerts (Level ≥ 12)",
      "type": "stat",
      "gridPos": { "x": 6, "y": 0, "w": 6, "h": 4 },
      "datasource": { "type": "grafana-opensearch-datasource", "uid": "wazuh-indexer" },
      "targets": [
        {
          "refId": "A",
          "query": "rule.level:>=12",
          "timeField": "timestamp",
          "metrics": [{ "id": "1", "type": "count" }],
          "bucketAggs": []
        }
      ],
      "options": {
        "colorMode": "background",
        "graphMode": "none",
        "justifyMode": "center",
        "textMode": "auto",
        "reduceOptions": { "calcs": ["sum"], "fields": "", "values": false }
      },
      "fieldConfig": {
        "defaults": {
          "color": { "mode": "thresholds" },
          "thresholds": {
            "mode": "absolute",
            "steps": [
              { "color": "green", "value": null },
              { "color": "orange", "value": 1 },
              { "color": "red", "value": 10 }
            ]
          },
          "unit": "short",
          "mappings": []
        },
        "overrides": []
      }
    },

    {
      "id": 3,
      "title": "Top Source IPs",
      "type": "table",
      "gridPos": { "x": 12, "y": 0, "w": 6, "h": 8 },
      "datasource": { "type": "grafana-opensearch-datasource", "uid": "wazuh-indexer" },
      "targets": [
        {
          "refId": "A",
          "query": "_exists_:data.srcip",
          "timeField": "timestamp",
          "metrics": [{ "id": "1", "type": "count" }],
          "bucketAggs": [
            {
              "id": "2",
              "type": "terms",
              "field": "data.srcip",
              "settings": { "size": "10", "order": "desc", "orderBy": "1" }
            }
          ]
        }
      ],
      "transformations": [
        {
          "id": "organize",
          "options": {
            "excludeByName": { "Time": true },
            "indexByName": {},
            "renameByName": {}
          }
        }
      ],
      "options": { "footer": { "show": false }, "showHeader": true },
      "fieldConfig": { "defaults": {}, "overrides": [] }
    },

    {
      "id": 4,
      "title": "Alert Timeline",
      "type": "timeseries",
      "gridPos": { "x": 0, "y": 4, "w": 12, "h": 8 },
      "datasource": { "type": "grafana-opensearch-datasource", "uid": "wazuh-indexer" },
      "targets": [
        {
          "refId": "A",
          "query": "*",
          "timeField": "timestamp",
          "metrics": [{ "id": "1", "type": "count" }],
          "bucketAggs": [
            {
              "id": "2",
              "type": "date_histogram",
              "field": "timestamp",
              "settings": { "interval": "auto", "min_doc_count": "0" }
            }
          ]
        }
      ],
      "options": {
        "tooltip": { "mode": "single", "sort": "none" },
        "legend": { "displayMode": "list", "placement": "bottom", "calcs": [] }
      },
      "fieldConfig": {
        "defaults": {
          "color": { "mode": "palette-classic" },
          "custom": {
            "lineWidth": 2,
            "fillOpacity": 10,
            "drawStyle": "line",
            "lineInterpolation": "linear",
            "showPoints": "never"
          }
        },
        "overrides": []
      }
    },

    {
      "id": 5,
      "title": "Asset Inventory + Alert Count",
      "description": "NetBox assets joined with Wazuh alert count. Joined on agent.name = NetBox device hostname. IP from NetBox.",
      "type": "table",
      "gridPos": { "x": 0, "y": 12, "w": 18, "h": 10 },
      "datasource": { "type": "datasource", "uid": "-- Mixed --" },
      "targets": [
        {
          "refId": "A",
          "datasource": { "type": "postgres", "uid": "netbox-postgres" },
          "rawSql": "SELECT d.name AS hostname, SPLIT_PART(d.name, '.', 1) AS short_hostname, COALESCE(ip.address::text, '') AS ip, d.status, dt.model AS device_type FROM dcim_device d LEFT JOIN ipam_ipaddress ip ON d.primary_ip4_id = ip.id LEFT JOIN dcim_devicetype dt ON d.device_type_id = dt.id ORDER BY d.name",
          "format": "table"
        },
        {
          "refId": "B",
          "datasource": { "type": "grafana-opensearch-datasource", "uid": "wazuh-indexer" },
          "query": "*",
          "timeField": "timestamp",
          "metrics": [{ "id": "1", "type": "count" }],
          "bucketAggs": [
            {
              "id": "2",
              "type": "terms",
              "field": "agent.name",
              "settings": { "size": "500", "order": "desc", "orderBy": "1" }
            }
          ]
        }
      ],
      "transformations": [
        {
          "id": "renameByName",
          "options": {
            "renameByName": {
              "agent.name": "short_hostname",
              "Count": "alert_count"
            }
          }
        },
        {
          "id": "joinByField",
          "options": { "byField": "short_hostname", "mode": "outer" }
        },
        {
          "id": "organize",
          "options": {
            "excludeByName": { "Time": true },
            "indexByName": {
              "hostname": 0,
              "short_hostname": 1,
              "ip": 2,
              "device_type": 3,
              "status": 4,
              "alert_count": 5
            },
            "renameByName": {}
          }
        }
      ],
      "options": {
        "footer": { "show": false },
        "showHeader": true,
        "sortBy": [{ "desc": true, "displayName": "alert_count" }]
      },
      "fieldConfig": {
        "defaults": {},
        "overrides": [
          {
            "matcher": { "id": "byName", "options": "alert_count" },
            "properties": [
              { "id": "custom.displayMode", "value": "color-background" },
              {
                "id": "thresholds",
                "value": {
                  "mode": "absolute",
                  "steps": [
                    { "color": "green", "value": null },
                    { "color": "yellow", "value": 10 },
                    { "color": "red", "value": 50 }
                  ]
                }
              }
            ]
          }
        ]
      }
    },

    {
      "id": 6,
      "title": "Recent Alerts",
      "type": "logs",
      "gridPos": { "x": 0, "y": 22, "w": 18, "h": 10 },
      "datasource": { "type": "grafana-opensearch-datasource", "uid": "wazuh-indexer" },
      "targets": [
        {
          "refId": "A",
          "query": "*",
          "timeField": "timestamp",
          "metrics": [{ "id": "1", "type": "raw_document", "settings": { "size": "50" } }],
          "bucketAggs": []
        }
      ],
      "options": {
        "dedupStrategy": "none",
        "enableLogDetails": true,
        "showLabels": false,
        "showTime": true,
        "sortOrder": "Descending",
        "wrapLogMessage": false
      }
    },

    {
      "id": 7,
      "title": "RAG Chat",
      "type": "text",
      "gridPos": { "x": 18, "y": 0, "w": 6, "h": 32 },
      "options": {
        "mode": "html",
        "content": "<iframe src=\"${chat_ui_url}\" width=\"100%\" height=\"100%\" frameborder=\"0\" style=\"min-height:900px;border:none;\"></iframe>"
      }
    }

  ]
}
DASH_EOF

echo "✓ Grafana dashboard provisioning written."

# ============================================================
# SECTION 10 — STARTUP SEQUENCE
#
# Phase 1 — Infrastructure: all storage, cache, CMDB healthy
#            before anything that depends on them starts.
# Phase 2 — Wazuh: joins rag-platform, fully healthy before
#            agent or Grafana tries to query wazuh.indexer.
# Phase 3 — Application layer: agent, chat-ui, then Grafana
#            separately with --wait (plugin download needs time).
# ============================================================

# Phase 1 — Infrastructure
cd "$INSTALL_DIR"
echo "→ [Phase 1/3] Starting infrastructure (OpenSearch, Postgres, Redis, NetBox, Ollama)..."
echo "  Allow several minutes on first boot: OpenSearch cluster init + NetBox DB migrations."
if ! docker compose up -d --wait --wait-timeout 300 opensearch postgres redis redis-cache netbox ollama; then
  echo "ERROR: infrastructure did not become healthy within 300s. Check:"
  echo "  cd ${INSTALL_DIR} && docker compose ps"
  echo "  cd ${INSTALL_DIR} && docker compose logs"
  exit 1
fi
echo "✓ OpenSearch, Postgres, and NetBox are healthy. Redis/Valkey and Ollama are running."

# Phase 2 — Wazuh
cd wazuh/wazuh-docker/single-node
echo "→ [Phase 2/3] Starting Wazuh (indexer + manager + dashboard)..."
if ! docker compose -f docker-compose.yml -f docker-compose.override.yml up -d --wait --wait-timeout 300; then
  echo "ERROR: Wazuh stack did not become healthy within 300s. Check:"
  echo "  cd $(pwd) && docker compose ps"
  echo "  cd $(pwd) && docker compose logs"
  exit 1
fi
echo "✓ Wazuh stack is healthy."

# Phase 3 — Application + Grafana
cd "$INSTALL_DIR"
echo "→ [Phase 3/3] Starting Agent and Chat UI..."
if ! docker compose up -d agent chat-ui; then
  echo "ERROR: agent or chat-ui failed to start. Check:"
  echo "  cd ${INSTALL_DIR} && docker compose logs agent chat-ui"
  exit 1
fi
echo "✓ Agent and Chat UI are running."

echo "→ [Phase 3/3] Starting Grafana (plugin downloads on first start — allow up to 60s)..."
if ! docker compose up -d --wait --wait-timeout 180 grafana; then
  echo "ERROR: Grafana did not become healthy within 180s."
  echo "  Most common cause: grafana-opensearch-datasource plugin download timed out."
  echo "  Retry: cd ${INSTALL_DIR} && docker compose up -d --wait grafana"
  echo "  Logs:  cd ${INSTALL_DIR} && docker compose logs grafana"
  exit 1
fi
echo "✓ Grafana is healthy."

# ============================================================
# SECTION 11 — MODEL PULL
# Ollama is running from Phase 1. Pull now so the first query
# does not stall waiting for a large download.
# ============================================================
echo "→ Pulling Ollama model phi4-reasoning:14b-plus-q4_K_M — large download, may take several minutes..."
if ! docker compose exec ollama ollama pull phi4-reasoning:14b-plus-q4_K_M; then
  echo "ERROR: model pull failed. Retry manually:"
  echo "  cd ${INSTALL_DIR} && docker compose exec ollama ollama pull phi4-reasoning:14b-plus-q4_K_M"
  exit 1
fi
echo "✓ Model phi4-reasoning:14b-plus-q4_K_M ready."

# ============================================================
# SECTION 12 — SUMMARY
# ============================================================
echo
echo "=== Install complete ==="
echo ""
echo "  Wazuh dashboard:   https://localhost:443        admin / SecretPassword  (Wazuh default)"
echo "  Wazuh indexer:     https://localhost:9200        admin / SecretPassword  (TLS, self-signed)"
echo "  NetBox:            http://localhost:8000         admin / ${PASS}"
echo "  Chat UI:           http://localhost:3000"
echo "  Agent API:         http://localhost:8080"
echo "  Grafana:           http://localhost:3001         admin / ${PASS}"
echo "  OpenSearch:        http://localhost:9201         no auth  (non-Wazuh log sources)"
echo "  Postgres:          localhost:5432                netbox / ${PASS}  db: netbox"
echo "  Ollama:            http://localhost:11434        model: phi4-reasoning:14b-plus-q4_K_M"
echo ""
echo "Grafana datasources (pre-configured — Connections → Data sources):"
echo "  Wazuh Indexer     → https://wazuh.indexer:9200  (admin / SecretPassword, TLS skip verify)"
echo "  OpenSearch (logs) → http://opensearch:9200       (no auth)"
echo "  NetBox (Postgres) → postgres:5432/netbox         (netbox / ${PASS})"
echo ""
echo "RAG query paths:"
echo "  Wazuh alerts  → agent queries https://wazuh.indexer:9200  (TLS, verification off)"
echo "  Other logs    → agent queries http://opensearch:9200       (no auth)"
echo "  Asset data    → agent reads postgres directly              (not via NetBox API)"
echo "  Chat history  → agent reads/writes redis-cache             (key prefix: chat:)"
echo ""
echo "All non-Wazuh components share password: ${PASS}"
echo "Before going beyond a lab: rotate PASS in ${INSTALL_DIR}/docker-compose.yml"
echo "and rotate Wazuh's three credentials per the Wazuh docs link above."
