# Changelog

All notable changes to the Volcano AI Firewall project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [3.0.0] - 2026-10-15

### Breaking Changes
- **Production Profile SQLite Refusal (Task 2)**:
  - When `VOLCANO_PROFILE=production`, Volcano strictly refuses to boot against SQLite (`sqlite://`), raising a `RuntimeError` immediately upon startup. This eliminates file-locking bottlenecks and database corruption in multi-worker production deployments.
  - Development environments (`VOLCANO_PROFILE=development`) continue using SQLite with Write-Ahead Logging (`WAL`) by default.
  - To explicitly allow SQLite in production (e.g. for resource-constrained edge appliances), set `VOLCANO_ALLOW_SQLITE_PRODUCTION=true`.
- **Sensor Token Requirement for HTTP Ingest (Task 3)**:
  - Remote telemetry ingestion via `POST /api/ingest/events` now requires a valid, active sensor bearer token (`Authorization: Bearer <token>`). Unauthenticated requests or requests with revoked tokens are rejected with HTTP `401 Unauthorized`. Ingest tokens must be provisioned by an administrator via `POST /api/admin/sensor-tokens`.
- **Rate Limiter Fail-Closed in Production (Task 1)**:
  - When `VOLCANO_RATE_LIMIT_BACKEND=redis` is selected and the Redis server is unreachable, authentication endpoints fail closed and return HTTP `503 Service Unavailable` with a logged critical error, preventing brute-force attacks during infrastructure outages.
  - In development mode (`VOLCANO_PROFILE=development`), Volcano logs a warning and falls back to in-memory rate limiting.

### Added
- **Distributed Rate Limiting (Redis Backend) (Task 1)**:
  - Added `RedisRateLimiter` (`backend/security/rate_limiter_redis.py`) implementing an atomic sliding-window algorithm via Redis Lua scripts for correct token accounting across multi-worker clusters.
  - Configurable via `VOLCANO_RATE_LIMIT_BACKEND` (`memory` default, `redis` opt-in) and `VOLCANO_REDIS_URL`.
  - Added optional dependencies in `requirements-extras.txt` (`redis`, `fakeredis`, `lupa`).
- **PostgreSQL Production Profile & Connection Pooling (Task 2)**:
  - Added `VOLCANO_PROFILE` environment setting (`development` default, or `production`).
  - Added configurable SQLAlchemy `QueuePool` settings in `backend/config.py` and `backend/storage/database.py`: `VOLCANO_DB_POOL_SIZE` (default 10), `VOLCANO_DB_MAX_OVERFLOW` (default 20), `VOLCANO_DB_POOL_PRE_PING` (default true), `VOLCANO_DB_POOL_RECYCLE` (default 3600s), and `VOLCANO_DB_CONNECT_TIMEOUT` (default 10s).
  - Added `docker-compose.prod.yml` and `.env.prod.example` for PostgreSQL 16 and optional Redis 7.
  - Added PostgreSQL 16 migration testing with service containers in GitHub Actions CI workflow (`.github/workflows/ci.yml`).
- **Sensor and Collector Split (Task 3)**:
  - Created standalone sensor module (`backend/sensor/`) decoupling raw network sniffing from core API processing.
  - Defined versioned telemetry event schema (`schema_version: "1.0"`) in `backend/sensor/schema.py`, strictly rejecting unsupported schema versions with HTTP 422.
  - Implemented `EventTransport` abstraction with `InProcessTransport` (default) and `HttpBatchTransport` posting to `POST /api/ingest/events`.
  - Implemented `BoundedEventBuffer` with drop-oldest burst protection, exposing atomic `dropped_events` telemetry to prevent packet capture starvation.
  - Added network telemetry adapters: Zeek TSV `conn.log` parser (`ZeekConnLogAdapter`) and NetFlow v9 binary parser (`NetFlowV9Adapter`).
  - Added sensor token database model (`sensor_tokens`), Alembic migration `004_add_sensor_tokens.py`, SHA-256 hashed token storage, and admin management endpoints (`POST /api/admin/sensor-tokens`, `GET /api/admin/sensor-tokens`, `DELETE /api/admin/sensor-tokens/{id}`).
- **Time-Series Metrics Storage (Task 4)**:
  - Added `MetricsSink` interface with `InMemorySink` (default bounded circular buffer) and `PrometheusSink` (`backend/storage/metrics_sink.py`) using `prometheus_client`.
  - Exposes `volcano_packet_rate`, `volcano_alerts_total` (by severity), `volcano_dropped_events_total`, `volcano_rate_limit_rejections_total`, `volcano_containment_actions_total` (by type), and `volcano_enforcement_mode`.
  - Added `GET /metrics` Prometheus endpoint, active only when `VOLCANO_METRICS_ENABLED=true` and guarded by optional `VOLCANO_METRICS_BEARER_TOKEN`.
  - Added Prometheus scrape configuration (`deploy/observability/prometheus.yml`) and Grafana dashboard (`deploy/observability/grafana_dashboard.json`).
- **Event Search (OpenSearch) (Task 5)**:
  - Added `AlertIndexer` interface with `SqlAlertIndexer` (default) and `OpenSearchIndexer` behind `VOLCANO_SEARCH_BACKEND=opensearch` (`backend/storage/alert_indexer.py`).
  - Added non-blocking bounded queue with exponential backoff retry; OpenSearch cluster outages never block alert generation or packet analysis.
  - Added `GET /api/search/alerts?q=` providing full-text multi-match search, returning HTTP 501 when disabled.
- **Horizontal WebSocket Scaling (Task 6)**:
  - Added `BaseWsBroker` interface with `InProcessWsBroker` (default) and `RedisPubSubBroker` behind `VOLCANO_WS_BROKER=redis` (`backend/security/ws_broker.py`).
  - Implemented cross-replica pub/sub broadcasting with `origin_id` suppression to eliminate infinite reflection loops.
- **Kubernetes Helm Chart (Task 7)**:
  - Added cloud-native Helm chart in `deploy/helm/volcano/` with Deployment, Service, Ingress, ConfigMap, Secret references (`secretKeyRef`), readiness/liveness probes on `/api/health`, resource requests/limits, PodDisruptionBudget, and optional sensor DaemonSet with `hostNetwork: true`.
  - Added `values.yaml` (production defaults, 2 replicas) and `values-dev.yaml`. Added Helm lint and template validation to CI.
- **Packet Capture Performance Evaluation (Task 8)**:
  - Added `backend/benchmarks/capture_bench.py` benchmarking single-core Scapy packet processing throughput, latency, and memory utilization.
  - Authored `docs/performance.md` documenting measured performance (~1,667 pkts/sec, 0.60 ms latency, 89.1% CPU), Python GIL bottlenecks, and transition roadmap to `AF_PACKET` and `eBPF/XDP`.

### Test Suite
- Expanded test coverage from 84 to **116 unit and integration tests** across 19 modules with a 100% pass rate.

---

## [2.1.0] - 2026-10-15

### Added
- **C2 Beaconing Detection (Task 3)**:
  - Added `backend/security/beacon_detector.py` calculating inter-arrival times and coefficient of variation ($C_v = \sigma / \mu$) per `(src_ip, dst_ip, dst_port)` tuple.
  - Flags periodic heartbeats when event count reaches `VOLCANO_BEACON_MIN_EVENTS` (default: 10), jitter $\le$ `VOLCANO_BEACON_MAX_JITTER` (default: 0.15), and mean interval $> 1.0\text{s}$.
  - Incorporated tuple-scoped cooldown suppression to eliminate alert storms.
  - Wired into `PacketAnomalyEngine` detection pipeline in `backend/app.py`.
- **Internal Lateral Movement Detection (Task 4)**:
  - Added `backend/security/lateral_movement_detector.py` tracking connections to internal destinations on administrative ports (SMB 445, WinRM 5985/5986, RDP 3389, SSH 22).
  - Emits high-severity `Possible Lateral Movement` alerts when an internal host contacts $\ge$ `VOLCANO_LATERAL_MIN_HOSTS` (default: 5) internal hosts within `VOLCANO_LATERAL_WINDOW` (default: 300s).
  - Enforced strict RFC 1918 internal IP validation and loopback exclusion.
- **Model Evaluation & Quality Gate Harness (Task 2)**:
  - Added `backend/ai_engine/evaluate_model.py` supporting stratified train/test splitting, 5-fold cross-validation, precision, recall, F1, ROC-AUC, and false-positive rate metrics.
  - Implemented probability calibration (isotonic regression / Platt sigmoid) with Brier score evaluation.
  - Added CI/CD quality gate enforcement (`--min-auc`, `--max-fpr`) with non-zero exit codes.
  - Added model drift detection comparing new test datasets against baseline evaluation reports.
  - Generates headless matplotlib ROC curve visualizations and structured JSON evaluation reports.
- **Autonomous Response Playbooks (Task 5)**:
  - Added `backend/ai/playbooks.py` featuring YAML schema validation, directory loading (`backend/playbooks/`), and sequential fail-closed execution.
  - Supported core response actions: `block_ip`, `notify`, `attach_pcap`, and `create_alert_note`.
  - Added strict safety invariants: allowlist immunity, prohibition of killswitch actions, and comprehensive per-step audit logging.
  - Added REST API endpoints: `GET /api/playbooks` and `POST /api/playbooks/reload`.
  - Shipped example playbooks for SSH brute force and C2 beaconing in `backend/playbooks/examples/`.
- **Real Enforcement Backend (nftables) (Task 6)**:
  - Defined abstract `EnforcementBackend` interface in `backend/security/enforcement/base.py`.
  - Implemented Linux kernel netfilter integration in `backend/security/enforcement/nftables.py` operating on a dedicated `inet volcano` table and `blocked_ips` set.
  - Enforced strict argument list subprocess execution (`shell=False`), `ipaddress` validation, allowlist immunity, and dry-run defaults.
- **Containment Rollback Snapshots & System-wide Dry-Run (Task 7)**:
  - Added bounded 10-snapshot history queue in `ResponseEngine` taking point-in-time snapshots before any state change.
  - Added `POST /api/containment/rollback` endpoint (admin only) with dry-run diff preview and live restore.
  - Extended dry-run execution mode across all containment paths, exposing telemetry in `GET /api/health`.

### Changed & Security Hardening
- **PyJWT Migration (Task 1)**:
  - Replaced deprecated and vulnerable `python-jose` with `PyJWT` across `backend/storage/auth.py` and `backend/requirements.txt`.
  - Maintained HS256 claim semantics and added unit test assertions for wrong key and expired token rejections.
  - `pip-audit` reports zero vulnerabilities associated with `python-jose`.
- **Brute-Force Login Auto-Containment (Task 1)**:
  - Connected failed authentication attempts reaching `BruteForceDetector.record_login_failure` to `ResponseEngine` with `VOLCANO_LOGIN_FAILURE_AUTO_BLOCK` configuration (default: `false`).
  - Enforced strict allowlist immunity preventing lockout of trusted administrative IPs.
- **Static Typing Improvements (Task 1)**:
  - Added type annotations across `RuleEngine._cache`, `StateEngine` tracking sets, and `RiskEngine` dataclass defaults, decreasing mypy error count from 40 to 30.

---

## [2.0.1] - 2026-10-14

### Documentation
- **Synchronized Documentation with Source Code**: Reconciled documentation across `docs/` and `README.md` to match the exact implementations in `backend/`:
  - **Brute-Force Detection Thresholds**: Corrected default brute-force sliding window to `10.0s`, threshold to `5` attempts, monitored ports to `[22, 3389, 21, 445]`, and alert severity to `high` with a `30.0s` cooldown.
  - **Machine Learning Phishing Model**: Corrected serialized model artifact name to `phishing_model.joblib` across operational guides and updated the 10-feature vector list to include `keyword_hits`.
  - **API Examples**: Reconciled `/api/check-url` and `/api/security/brute-force/stats` request and response payloads to match the actual return schemas of `PhishingDetector.predict()` and `BruteForceDetector.get_stats()`.
  - **Autonomous Containment Responses**: Updated `/api/autonomous/block-ip` documentation to detail HTTP 200 success schema `{"id": <int>, "status": "blocked", "duration": <int>}` and HTTP 400 error schema `{"detail": "Rejected: IP <ip> is protected by system allowlist."}`.
  - **Allowlist Defaults**: Documented code defaults (`["127.0.0.1", "::1", "0.0.0.0"]`) and programmatic loopback/unspecified protections alongside configurable subnets and gateway routers.
  - **Test Suite Accounting**: Updated per-file test breakdown in `docs/operations_and_deployment.md` to precisely reflect the 30 tests collected via `pytest --collect-only -q`:
    - `test_allowlist_response.py`: 3 tests
    - `test_auth.py`: 15 tests (expanded with safe startup, forced password change, rate-limiting, lockout, and anti-enumeration)
    - `test_database_maintenance.py`: 6 tests
    - `test_detections.py`: 8 tests
    - `test_feeds.py`: 3 tests
    - `test_pcap.py`: 2 tests
    - `test_triage.py`: 3 tests
    - Total: 40 tests (100% pass rate)

### Security & Hardening
- **Safe Startup & Default Secret Elimination (Task 2)**:
  - Removed sample default JWT secret from `config.py` and `.env.example`.
  - Added startup validation refusing execution if `VOLCANO_JWT_SECRET_KEY` is missing or set to a known sample secret in production.
  - Added development mode auto-key generation storing a high-entropy key in `backend/.secret_key` with strict `0600` permissions.
  - Replaced hardcoded admin password (`changeme123`) with dynamically generated cryptographically secure initial password printed once to console.
  - Added Alembic migration `002_add_must_change_password.py` and enforced `must_change_password` check blocking login until updated via `POST /api/auth/change-password`.
- **Authentication & Login Hardening (Task 3)**:
  - Added extensible `BaseRateLimiter` interface with thread-safe `InMemoryRateLimiter` sliding window limiter.
  - Enforced login rate limits on `POST /api/auth/login`: 5 failed attempts per username and 20 per source IP within 5 minutes, returning HTTP 429 with `Retry-After`.
  - Added account lockout after 10 consecutive failures (15-minute lock or administrative unlock via `POST /api/auth/users/{username}/unlock`), tracked via Alembic migration `003_add_account_lockout.py`.
  - Emitted audit log entries for failed logins and connected failed attempts to the brute-force detection pipeline.
  - Mitigated account enumeration through constant-time bcrypt verification with dummy hash and identical HTTP 401 error responses for non-existent and existing accounts.
