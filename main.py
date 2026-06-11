"""
iTechSmart Seal Service — controlled writer for the ProofLink ledger.

The ONLY component that mounts/writes the canonical ledger. Callers (e.g. the
AG2 agent container) POST /seal with a Bearer token; this service validates,
rate-limits, restricts categories, and shells out to the canonical append.py
server-side. This keeps raw ledger write access off the LLM-agent container.
"""
import json
import os
import subprocess
import threading
import time
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

APPEND_PY = os.environ.get("APPEND_PY", "/opt/itechsmart/audit_ledger/append.py")
SEAL_TOKEN = os.environ.get("SEAL_TOKEN", "")
# Only allow categories with these prefixes (agent seals). Keeps a compromised
# caller from writing arbitrary platform receipt categories.
ALLOWED_PREFIXES = tuple(
    p.strip() for p in os.environ.get("SEAL_ALLOWED_PREFIXES", "ag2_").split(",") if p.strip()
)
RATE_MAX = int(os.environ.get("SEAL_RATE_MAX", "120"))        # max seals ...
RATE_WINDOW = int(os.environ.get("SEAL_RATE_WINDOW", "60"))   # ... per N seconds

app = FastAPI(title="iTechSmart Seal Service", docs_url=None, redoc_url=None)

_lock = threading.Lock()
_events: list = []


class SealRequest(BaseModel):
    category: str
    actor: str
    subject: str
    action: str
    outcome: str = ""
    details: dict = Field(default_factory=dict)
    incident_id: Optional[str] = None
    ots: bool = False  # default: skip OpenTimeStamps (fast); batch-anchor elsewhere

    # Receipt Schema v2 (2026-06-11) — optional decision/outcome/ITSM/policy
    # intelligence. Carried inside details so the canonical append.py CLI
    # stays untouched; readers fall back details-wise (receipt_schema_v2.extract_v2).
    decision_reason: Optional[str] = None
    confidence_score: Optional[float] = None
    model_used: Optional[str] = None
    agent_id: Optional[str] = None
    causal_chain: Optional[list] = None
    alternatives_considered: Optional[list] = None
    success: Optional[bool] = None
    mttr_seconds: Optional[int] = None
    pre_action_snapshot_id: Optional[str] = None
    post_action_health: Optional[float] = None
    itsm_ticket_id: Optional[str] = None
    itsm_ticket_url: Optional[str] = None
    itsm_ticket_closed: Optional[bool] = None
    sla_status: Optional[str] = None
    sla_response_seconds: Optional[int] = None
    sla_resolution_seconds: Optional[int] = None
    policy_source: Optional[str] = None
    policies_enforced: Optional[list] = None
    policy_violations: Optional[list] = None
    compliance_frameworks: Optional[list] = None


V2_FIELDS = (
    "decision_reason", "confidence_score", "model_used", "agent_id",
    "causal_chain", "alternatives_considered", "success", "mttr_seconds",
    "pre_action_snapshot_id", "post_action_health", "itsm_ticket_id",
    "itsm_ticket_url", "itsm_ticket_closed", "sla_status",
    "sla_response_seconds", "sla_resolution_seconds", "policy_source",
    "policies_enforced", "policy_violations", "compliance_frameworks",
)


def _rate_ok() -> bool:
    now = time.time()
    with _lock:
        cutoff = now - RATE_WINDOW
        while _events and _events[0] < cutoff:
            _events.pop(0)
        if len(_events) >= RATE_MAX:
            return False
        _events.append(now)
        return True


@app.get("/health")
def health():
    return {
        "ok": True,
        "service": "itechsmart-seal",
        "append_py": APPEND_PY,
        "allowed_prefixes": list(ALLOWED_PREFIXES),
        "rate_limit": f"{RATE_MAX}/{RATE_WINDOW}s",
        "auth": bool(SEAL_TOKEN),
    }


@app.post("/seal")
def seal(req: SealRequest, authorization: str = Header(default="")):
    if not SEAL_TOKEN or authorization != f"Bearer {SEAL_TOKEN}":
        raise HTTPException(status_code=401, detail="unauthorized")
    if ALLOWED_PREFIXES and not any(req.category.startswith(p) for p in ALLOWED_PREFIXES):
        raise HTTPException(status_code=400, detail=f"category must start with one of {list(ALLOWED_PREFIXES)}")
    for name, val in (("category", req.category), ("actor", req.actor), ("subject", req.subject), ("action", req.action)):
        if not val or len(val) > 2000:
            raise HTTPException(status_code=400, detail=f"missing or oversized field: {name}")
    if not _rate_ok():
        raise HTTPException(status_code=429, detail="rate limit exceeded")

    details = dict(req.details or {})
    if req.incident_id:
        details.setdefault("incident_id", req.incident_id)
    # Receipt Schema v2 passthrough — non-null v2 fields ride inside details
    for f in V2_FIELDS:
        v = getattr(req, f, None)
        if v is not None:
            details[f] = v
    if any(getattr(req, f, None) is not None for f in V2_FIELDS):
        details.setdefault("schema_version", "2.0")
    args = [
        "python3", APPEND_PY,
        "--category", req.category[:200],
        "--actor", req.actor[:200],
        "--subject", req.subject[:200],
        "--action", req.action[:1000],
        "--outcome", req.outcome[:1000],
        "--details", json.dumps(details)[:8000],
        "--human-input", "false",
        "--auto-resolved", "true",
    ]
    # Per-incident chain: every receipt sharing an incident_id is linked into one
    # chain_id, yielding a verifiable per-incident receipt chain (via append.py --chain-id).
    if req.incident_id:
        args += ["--chain-id", req.incident_id[:200]]
    if not req.ots:
        args.append("--no-ots")

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=90)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"seal subprocess failed: {e}")
    if proc.returncode != 0:
        raise HTTPException(status_code=500, detail=f"append.py failed: {(proc.stderr or '').strip()[:300]}")
    try:
        out = json.loads(proc.stdout.strip().splitlines()[-1])
    except Exception:
        raise HTTPException(status_code=500, detail=f"append.py bad output: {proc.stdout[:200]}")
    return {"ok": True, "receipt_id": out.get("id"), "hash": out.get("hash"), "chain_id": out.get("chain_id")}
