# Deployment

From a laptop to a hardened production deployment.

---

## 1. Deployment shapes

| Shape | When | Storage | Cache | Workers |
| --- | --- | --- | --- | --- |
| **Single process** | Laptop, CI, ad-hoc analysis | Local Parquet | Memory | In-process threads |
| **Single node** | Up to ~50 M records/day | Local Parquet + PostgreSQL | Redis | Celery on the same host |
| **Multi node** | Beyond that, or HA | Shared/NFS/object storage | Redis | Celery workers, separate hosts |

The code is identical in all three; only configuration changes.

---

## 2. Pre-flight

```bash
loganalytics config validate --environment production
```

This is not advisory. With `environment: production` the process **refuses to
start** if debug is on, authentication is off, no credentials are configured,
CORS is `*`, masking is off, docs are enabled, or the log level is `DEBUG`.

Then confirm:

- [ ] `LOGA_DATABASE__PASSWORD` and `LOGA_CACHE__REDIS_PASSWORD` set from a secret store
- [ ] API keys minted and delivered out of band (`loganalytics apikey create`)
- [ ] `ingestion.allowed_roots` lists only the directories that must be read
- [ ] `storage.data_root` is on a volume with capacity for the retention window
- [ ] TLS terminated in front; `api.hsts_enabled: true`
- [ ] `api.trusted_proxies` set to the proxy's CIDR (otherwise `X-Forwarded-For` is ignored)
- [ ] Retention job scheduled
- [ ] `/health/ready` wired to the load balancer, `/health/live` to the restart policy
- [ ] `/metrics` scraped

---

## 3. Docker Compose

```bash
cp .env.example .env
# set POSTGRES_PASSWORD and LOGA_API_KEYS
docker compose up -d
docker compose logs -f api
```

Services: `api`, `postgres`, `redis`; `--profile workers` adds a worker,
`--profile streaming` adds Kafka.

The API publishes to `127.0.0.1:8000` only — put a TLS-terminating proxy in
front rather than exposing it. PostgreSQL and Redis are not published at all.

Ingest by dropping files into `./data/raw` (mounted read-only at `/logs`):

```bash
docker compose exec api loganalytics ingest /logs/access.log
```

### Hardening the compose deployment

```yaml
services:
  api:
    read_only: true                 # the image declares its writable volumes
    tmpfs:
      - /tmp
    cap_drop: [ALL]
    security_opt:
      - no-new-privileges:true
    deploy:
      resources:
        limits:
          cpus: "2.0"
          memory: 2G
```

---

## 4. Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: log-analytics-api
spec:
  replicas: 2
  selector:
    matchLabels: {app: log-analytics, component: api}
  template:
    metadata:
      labels: {app: log-analytics, component: api}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        fsGroup: 10001
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: api
          image: ghcr.io/example/big-data-log-analytics:1.0.0
          args: ["serve"]
          ports: [{containerPort: 8000, name: http}]
          env:
            - name: LOGA_ENVIRONMENT
              value: production
            - name: LOGA_CONFIG_FILE
              value: /config/production.yaml
            - name: LOGA_DATABASE__PASSWORD
              valueFrom: {secretKeyRef: {name: loga-secrets, key: postgres-password}}
            - name: LOGA_CACHE__REDIS_PASSWORD
              valueFrom: {secretKeyRef: {name: loga-secrets, key: redis-password}}
            - name: LOGA_API__API_KEY_HASHES
              valueFrom: {secretKeyRef: {name: loga-secrets, key: api-key-hashes}}
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          resources:
            requests: {cpu: 500m, memory: 512Mi}
            limits:   {cpu: "2",  memory: 2Gi}
          livenessProbe:
            httpGet: {path: /health/live, port: http}
            initialDelaySeconds: 15
            periodSeconds: 30
          readinessProbe:
            httpGet: {path: /health/ready, port: http}
            initialDelaySeconds: 10
            periodSeconds: 10
          volumeMounts:
            - {name: data,   mountPath: /data}
            - {name: config, mountPath: /config, readOnly: true}
            - {name: tmp,    mountPath: /tmp}
      volumes:
        - name: data
          persistentVolumeClaim: {claimName: log-analytics-data}
        - name: config
          configMap: {name: log-analytics-config}
        - name: tmp
          emptyDir: {}
```

Liveness targets `/health/live` (no dependencies) and readiness targets
`/health/ready` (storage). Pointing liveness at a dependency-checking endpoint is
how a Redis blip turns into a restart loop.

### Scheduled maintenance

```yaml
apiVersion: batch/v1
kind: CronJob
metadata: {name: log-analytics-retention}
spec:
  schedule: "0 3 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: cleanup
              image: ghcr.io/example/big-data-log-analytics:1.0.0
              args: ["job", "run", "cleanup",
                     "--params", '{"retention_days": 90, "layer": "raw", "dry_run": false}']
```

Pair it with a `compact` job (merges small Parquet files) and a `report` job.

---

## 5. Reverse proxy

```nginx
server {
    listen 443 ssl http2;
    server_name logs.example.com;

    ssl_certificate     /etc/ssl/certs/logs.crt;
    ssl_certificate_key /etc/ssl/private/logs.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    client_max_body_size 2m;      # matches api.max_request_bytes

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;

        # Streamed exports must not be buffered.
        proxy_buffering off;
    }
}
```

Then set `api.trusted_proxies: ["127.0.0.1/32"]`, or the platform will keep
ignoring `X-Forwarded-For` — by design, so that an untrusted client cannot spoof
its own identity and bypass rate limiting.

---

## 6. Ingestion patterns

### Scheduled batch

```bash
0 * * * * loganalytics ingest /var/log/nginx/access.log --format access
```

Deterministic ids make re-ingestion idempotent, so an overlapping run is safe.

### Directory watch

```bash
loganalytics process --input /var/log/incoming -w 4 --pattern '*.log'
```

### From a database

```bash
loganalytics ingest "postgresql://reader@db/logs?options=-csearch_path%3Dpublic"
```

Grant the account `SELECT` on the log table and nothing else.

### From an API

```bash
loganalytics ingest "https://logs.vendor.example/api/v1/events"
```

Private and link-local targets are refused unless
`ingestion.allow_private_network_sources` is enabled.

---

## 7. Operations

### Monitoring

Scrape `/metrics`. Alert on:

| Signal | Suggested threshold |
| --- | --- |
| `loga_http_requests_failed_total` rate | > 1 % of requests |
| `/health/ready` non-200 | 2 consecutive failures |
| Rejection rate (`GET /admin/rejected`) | > 5 % of ingested records |
| Failed runs (`GET /admin/runs`) | any |
| Disk usage on `storage.data_root` | > 80 % |
| `loga_cache_hit_rate` | < 0.5 sustained (tune TTL) |

The platform's own logs are JSON on stderr — ingest them into the platform.

### Backup

- `data/processed` — the source of truth. Snapshot the volume or sync to object
  storage; partition directories are immutable once written.
- The metadata database — standard `pg_dump`.
- `data/rejected` — keep for as long as you might want to replay.

### Restore

Copy the Parquet tree back and restore the metadata database. No import step:
DuckDB reads the files in place.

### Upgrades

Parquet is self-describing and readers tolerate added columns
(`union_by_name=true`), so a rolling upgrade is safe. Take a metadata backup
first; run the new version's `config validate` before switching traffic.

---

## 8. Capacity planning

From the measured 3.81x compression and ~1,100 records/s/core on the reference
CPU (see [PERFORMANCE.md](PERFORMANCE.md)):

| Daily volume | Ingest time (4 cores, modern CPU) | Parquet/day | 90-day retention |
| --- | --- | --- | --- |
| 1 M | ~1 min | ~120 MB | ~11 GB |
| 10 M | ~8 min | ~1.2 GB | ~108 GB |
| 100 M | ~80 min | ~12 GB | ~1.1 TB |

Memory: ~1 GB per API replica, ~500 MB per ingestion worker plus
`deduplication.max_tracked_keys × 120 B`.

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Refuses to start in production | A hardening check failed | Read the message; run `config validate` |
| `path is outside the permitted roots` | Source not under `ingestion.allowed_roots` | Add the directory |
| High rejection rate | Wrong format detected | Pass `--format`; inspect `loganalytics dlq show` |
| `429` from a trusted client | Shared credential exhausting one bucket | Mint per-client keys; raise the limit |
| Rate limits per-request, not per-client | `trusted_proxies` unset behind a proxy | Set it to the proxy CIDR |
| Queries slow | No time range → no pruning | Always pass `start`/`end` or `hours`; run `compact` |
| Empty results after ingest | Different `data_root` between writer and reader | Compare `loganalytics config show` |
| `Missing greenlet` / driver errors | Extra not installed | `pip install -e ".[postgres]"` |
| Memory grows during ingest | `write_batch_size` or dedup cap too high | Lower both |

Every response carries `X-Request-ID`; grep the JSON logs for it to get the full
(masked) detail behind a generic error.
