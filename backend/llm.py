"""Shared OpenAI client + robust JSON-completion helper.

One place that owns the OpenAI integration for every reasoning surface
(reasoner.py, shield.py). Behaviour:

  - Reads OPENAI_API_KEY / OPENAI_MODEL once.
  - Requests strict JSON (response_format=json_object).
  - If the preferred model id is unknown to the account (404 / model-not-found),
    it degrades through a fallback chain of GPT-5-family models instead of
    failing — so "gpt-5.6" keeps working as the family evolves.
  - One retry on transient errors (rate limit / timeout / 5xx).
  - Raises on hard failure; callers own the deterministic fallback so the
    security gate never goes dark.
"""
import json
import os
import time
import logging

logger = logging.getLogger(__name__)

MODEL = os.environ.get("OPENAI_MODEL", "gpt-5.6")
_API_KEY = os.environ.get("OPENAI_API_KEY")

# Preferred model first, then progressively more available GPT-5-family ids.
_FALLBACK_CHAIN = [MODEL, "gpt-5.6", "gpt-5.1", "gpt-5", "gpt-5-mini"]
# De-duplicate while preserving order.
FALLBACK_MODELS = list(dict.fromkeys(m for m in _FALLBACK_CHAIN if m))

_client = None
# Remember a model that worked so we don't re-probe a dead id every call.
_resolved_model = None


def available() -> bool:
    return bool(_API_KEY)


def _get_client():
    global _client
    if _client is None:
        from openai import OpenAI
        _client = OpenAI(api_key=_API_KEY)
    return _client


def _is_model_missing(err: Exception) -> bool:
    s = str(err).lower()
    return "model" in s and ("not found" in s or "does not exist" in s or "404" in s)


def complete_json(system_prompt: str, user_prompt: str, temperature: float = 0.1) -> dict:
    """Return the model's JSON object. Tries the resolved/preferred model, then
    the fallback chain on model-not-found, with one retry on transient errors."""
    global _resolved_model
    if not available():
        raise RuntimeError("OPENAI_API_KEY not configured")
    client = _get_client()
    models = ([_resolved_model] if _resolved_model else []) + \
             [m for m in FALLBACK_MODELS if m != _resolved_model]

    last_err = None
    for model in models:
        for attempt in (1, 2):
            try:
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "system", "content": system_prompt},
                              {"role": "user", "content": user_prompt}],
                    temperature=temperature,
                    response_format={"type": "json_object"},
                )
                data = json.loads(resp.choices[0].message.content)
                if _resolved_model != model:
                    _resolved_model = model
                    if model != MODEL:
                        logger.warning("Model %s unavailable — using %s.", MODEL, model)
                data["engine"] = model
                return data
            except Exception as e:  # noqa: BLE001 — classify below
                last_err = e
                if _is_model_missing(e):
                    break  # try the next model in the chain
                if attempt == 1:  # transient — one quick retry
                    time.sleep(0.6)
                    continue
                raise
    raise last_err if last_err else RuntimeError("no model available")
