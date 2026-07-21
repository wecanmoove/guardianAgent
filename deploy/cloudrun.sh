#!/usr/bin/env bash
# Deploy GuardAgent Control Plane to Google Cloud Run.
# Prereqs: gcloud CLI authenticated, a GCP project, billing enabled, OPENAI_API_KEY set.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-guardagent-control-plane}"

echo "▶ Enabling required Google Cloud APIs…"
gcloud services enable run.googleapis.com \
  secretmanager.googleapis.com cloudbuild.googleapis.com --project "$PROJECT"

echo "▶ Storing secrets in Secret Manager…"
if ! gcloud secrets describe gitlab-webhook-secret --project "$PROJECT" >/dev/null 2>&1; then
  printf '%s' "${GITLAB_WEBHOOK_SECRET:-whsec_demo}" | \
    gcloud secrets create gitlab-webhook-secret --data-file=- --project "$PROJECT"
fi
if ! gcloud secrets describe openai-api-key --project "$PROJECT" >/dev/null 2>&1; then
  printf '%s' "${OPENAI_API_KEY:?set OPENAI_API_KEY}" | \
    gcloud secrets create openai-api-key --data-file=- --project "$PROJECT"
fi

echo "▶ Building & deploying to Cloud Run (OpenAI GPT-5.6)…"
gcloud run deploy "$SERVICE" \
  --source . \
  --project "$PROJECT" \
  --region "$REGION" \
  --allow-unauthenticated \
  --set-env-vars "OPENAI_MODEL=gpt-5.6" \
  --set-secrets "GITLAB_WEBHOOK_SECRET=gitlab-webhook-secret:latest,OPENAI_API_KEY=openai-api-key:latest" \
  --cpu 1 --memory 512Mi --max-instances 5

echo "✅ Deployed. Service URL:"
gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" \
  --format 'value(status.url)'
