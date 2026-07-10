#!/usr/bin/env bash
# Deploy GuardAgent Control Plane to Google Cloud Run.
# Prereqs: gcloud CLI authenticated, a GCP project, billing enabled.
set -euo pipefail

PROJECT="${GOOGLE_CLOUD_PROJECT:?set GOOGLE_CLOUD_PROJECT}"
REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-guardagent-control-plane}"

echo "▶ Enabling required Google Cloud APIs…"
gcloud services enable run.googleapis.com aiplatform.googleapis.com \
  secretmanager.googleapis.com cloudbuild.googleapis.com --project "$PROJECT"

echo "▶ Storing the GitLab webhook secret in Secret Manager…"
if ! gcloud secrets describe gitlab-webhook-secret --project "$PROJECT" >/dev/null 2>&1; then
  printf '%s' "${GITLAB_WEBHOOK_SECRET:-whsec_demo}" | \
    gcloud secrets create gitlab-webhook-secret --data-file=- --project "$PROJECT"
fi

echo "▶ Building & deploying to Cloud Run (Gemini via Vertex AI)…"
gcloud run deploy "$SERVICE" \
  --source . \
  --project "$PROJECT" \
  --region "$REGION" \
  --allow-unauthenticated \
  --set-env-vars "GOOGLE_GENAI_USE_VERTEXAI=true,GOOGLE_CLOUD_PROJECT=${PROJECT},GOOGLE_CLOUD_LOCATION=${REGION},GEMINI_MODEL=gemini-2.5-flash" \
  --set-secrets "GITLAB_WEBHOOK_SECRET=gitlab-webhook-secret:latest" \
  --cpu 1 --memory 512Mi --max-instances 5

echo "✅ Deployed. Service URL:"
gcloud run services describe "$SERVICE" --project "$PROJECT" --region "$REGION" \
  --format 'value(status.url)'
