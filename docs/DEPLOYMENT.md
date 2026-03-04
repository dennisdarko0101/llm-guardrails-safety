# Deployment Guide

## Local Development

```bash
# Install
pip install -e ".[dev]"

# Configure
cp .env.example .env
# Edit .env with your settings

# Run
make run
# → http://localhost:8000/docs
```

## Docker

### Build and Run

```bash
# Build
docker build -t llm-guardrails -f docker/Dockerfile .

# Run
docker run -p 8000:8000 --env-file .env llm-guardrails

# Or use docker-compose
cd docker && docker-compose up
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARDRAILS_SAFETY_LEVEL` | `moderate` | Global safety level |
| `GUARDRAILS_MAX_INPUT_LENGTH` | `10000` | Max input characters |
| `GUARDRAILS_TOXICITY_THRESHOLD` | `0.7` | Toxicity detection threshold |
| `GUARDRAILS_INJECTION_SENSITIVITY` | `medium` | Injection detection: low/medium/high |
| `GUARDRAILS_ENABLE_PII_REDACTION` | `true` | Auto PII redaction |
| `GUARDRAILS_ENABLE_LLM_DETECTION` | `false` | LLM-based detection (requires API key) |
| `GUARDRAILS_ANTHROPIC_API_KEY` | — | Anthropic API key (for LLM mode) |
| `GUARDRAILS_HOST` | `0.0.0.0` | Server host |
| `GUARDRAILS_PORT` | `8000` | Server port |
| `GUARDRAILS_LOG_LEVEL` | `INFO` | Log level |
| `GUARDRAILS_LOG_JSON` | `true` | JSON log format |

## Cloud Run (GCP)

```bash
# Build and push
gcloud builds submit --tag gcr.io/YOUR_PROJECT/llm-guardrails -f docker/Dockerfile .

# Deploy
gcloud run deploy llm-guardrails \
  --image gcr.io/YOUR_PROJECT/llm-guardrails \
  --platform managed \
  --region us-central1 \
  --port 8000 \
  --memory 512Mi \
  --min-instances 0 \
  --max-instances 10 \
  --set-env-vars "GUARDRAILS_SAFETY_LEVEL=moderate"
```

## AWS ECS / Fargate

1. Push image to ECR
2. Create task definition with port 8000, 512MB memory
3. Configure environment variables
4. Set health check to `GET /health`

## Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-guardrails
spec:
  replicas: 2
  selector:
    matchLabels:
      app: llm-guardrails
  template:
    metadata:
      labels:
        app: llm-guardrails
    spec:
      containers:
        - name: guardrails
          image: ghcr.io/yourrepo/llm-guardrails:latest
          ports:
            - containerPort: 8000
          env:
            - name: GUARDRAILS_SAFETY_LEVEL
              value: "moderate"
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 10
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: llm-guardrails
spec:
  selector:
    app: llm-guardrails
  ports:
    - port: 80
      targetPort: 8000
  type: ClusterIP
```

## Health Checks

- **Endpoint:** `GET /health`
- **Response:** `{"status": "healthy", "version": "0.1.0", "detectors": {...}}`
- **Metrics:** `GET /metrics` for request counts, latency, uptime
