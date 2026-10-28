"""
NetGraph Sentinel — Phase 8: RAG-based Alert Explanation

Retrieval-Augmented Generation layer. Does NOT detect threats — the graph,
rules, and ML layers (Phase 2/3) already do that. This sits AFTER
detection and turns a raw alert into a clear, human-readable explanation.

Pipeline:
    1. RETRIEVE : embed the alert and find the most relevant knowledge-base
                  entries (sentence-transformers + FAISS, fully local), then
                  re-rank them so the entry that matches the alert's threat
                  type comes first.
    2. GENERATE : a LOCAL LLM (Ollama) writes a short, alert-specific brief
                  from the REAL alert facts (IPs, confidence, evidence) plus
                  the retrieved notes.
    3. FALL BACK: if Ollama is down, slow or answers badly, a template that
                  also uses the real alert facts is returned. This optional
                  layer never breaks the rest of the system.

MITRE ids always come from the knowledge base, never from the LLM.
VYUH is passive and read-only: nothing here blocks or probes anything.

Requires (separately installed, not via pip):
    - Ollama running locally: https://ollama.com
    - A pulled model:  ollama pull llama3.2:3b

Optional environment variables:
    OLLAMA_URL         default http://localhost:11434
    OLLAMA_MODEL       default llama3.2:3b
    OLLAMA_TIMEOUT     default 60   (seconds; the first call loads the model)
    OLLAMA_KEEP_ALIVE  default 30m  (keeps the model in memory between calls)

Self-test (run inside backend/):   python rag_engine.py PortScan DDoS
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import threading
import time

import numpy as np
import requests

from knowledge_base import KNOWLEDGE_BASE

log = logging.getLogger("netgraph.rag")

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:3b")
OLLAMA_TIMEOUT = float(os.getenv("OLLAMA_TIMEOUT", "60"))
OLLAMA_KEEP_ALIVE = os.getenv("OLLAMA_KEEP_ALIVE", "30m")
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

MAX_EXPLANATION_CHARS = 700
MAX_ACTION_CHARS = 450

READ_ONLY_NOTE = (
    "VYUH is read-only, so any block or isolation must be requested through the separate analyst response channel."
)

# ---------------------------------------------------------------------------
# Threat type -> how to recognise its knowledge-base entry, plus a template
# sentence that uses the real alert facts
# ---------------------------------------------------------------------------
TYPE_HINTS: dict[str, dict] = {
    "PortScan": {
        "label": "Port Scan",
        "mitre": {"T1046"},
        "keywords": ["port scan", "port scanning", "service discovery", "reachable services"],
        "template": "{src} probed {dst} across many ports and hosts in a very short time, the star-shaped pattern of a port scan (confidence {conf}%).",
    },
    "DDoS": {
        "label": "DDoS",
        "mitre": {"T1498", "T1499"},
        "keywords": ["ddos", "denial of service", "flood", "many sources"],
        "template": "{dst} is receiving connections from many different sources at once, the hub-shaped pattern of a DDoS flood (confidence {conf}%).",
    },
    "C2Beaconing": {
        "label": "C2 Beaconing",
        "mitre": {"T1071", "T1573", "T1095", "T1102"},
        "keywords": ["beacon", "command and control", "c2", "check in", "checks in"],
        "template": "{src} contacted {dst} again and again at very regular intervals with near-identical small messages, the signature of malware checking in with its controller (confidence {conf}%).",
    },
    "DGA": {
        "label": "DGA Domains",
        "mitre": {"T1568.002", "T1568"},
        "keywords": ["dga", "domain generation", "generated domain", "random domain"],
        "template": "{src} contacted a large number of different one-off destinations over DNS, as malware does when it generates random domain names to find its controller (confidence {conf}%).",
    },
    "DNSTunneling": {
        "label": "DNS Tunneling",
        "mitre": {"T1071.004", "T1572"},
        "keywords": ["dns tunnel", "dns tunnell", "oversized dns", "hidden inside dns"],
        "template": "{src} sent DNS traffic to {dst} that is far larger than a normal lookup, which suggests data hidden inside DNS (confidence {conf}%).",
    },
    "Exfiltration": {
        "label": "Data Exfiltration",
        "mitre": {"T1041", "T1048", "T1030"},
        "keywords": ["exfiltrat", "data theft", "stolen data", "outbound"],
        "template": "{src} suddenly sent a very large volume of data out to {dst}, far above the rest of the network (confidence {conf}%), which can mean data is being stolen.",
    },
    # "Anomaly" has no MITRE technique: it is a generic statistical flag
    "Anomaly": {
        "label": "Statistical Anomaly",
        "mitre": set(),
        "keywords": [],
        "template": "{src} is sending traffic that looks statistically unlike the normal traffic the model learned (confidence {conf}%), without matching a named attack. It may be a new or slow-and-low pattern.",
    },
}

_ALIASES = {
    "portscan": "PortScan", "portscanning": "PortScan", "portscans": "PortScan",
    "ddos": "DDoS",
    "c2beaconing": "C2Beaconing", "c2beacon": "C2Beaconing", "c2": "C2Beaconing", "beaconing": "C2Beaconing",
    "dga": "DGA", "dgadomains": "DGA",
    "dnstunneling": "DNSTunneling", "dnstunnelling": "DNSTunneling", "dnstunnel": "DNSTunneling",
    "exfiltration": "Exfiltration", "exfil": "Exfiltration", "dataexfiltration": "Exfiltration",
    "anomaly": "Anomaly",
}


def _canonical_type(raw: str) -> str | None:
    return _ALIASES.get(re.sub(r"[^a-z0-9]", "", (raw or "").lower()))


# ---------------------------------------------------------------------------
# Embeddings + FAISS (built once, lazily; optional dependencies)
# ---------------------------------------------------------------------------
_state: dict = {"ready": False, "embedder": None, "vecs": None, "index": None}
_state_lock = threading.Lock()


def _passage(entry: dict) -> str:
    return f"{entry.get('mitre_name', '')}. {entry.get('text', '')}"


def _ensure_embeddings() -> bool:
    """Build the embedding index once. Returns False if embeddings are unavailable."""
    if _state["ready"]:
        return _state["vecs"] is not None
    with _state_lock:
        if _state["ready"]:
            return _state["vecs"] is not None
        try:
            from sentence_transformers import SentenceTransformer

            embedder = SentenceTransformer(EMBEDDING_MODEL_NAME)
            vecs = embedder.encode(
                [_passage(e) for e in KNOWLEDGE_BASE],
                convert_to_numpy=True,
                normalize_embeddings=True,
            ).astype("float32")
            _state["embedder"], _state["vecs"] = embedder, vecs
            try:
                import faiss

                index = faiss.IndexFlatIP(vecs.shape[1])  # inner product = cosine (vectors are normalised)
                index.add(vecs)
                _state["index"] = index
            except Exception:
                log.warning("faiss not available, using numpy for the similarity search")
        except Exception as exc:
            log.warning("embeddings unavailable (%s); retrieval uses type hints only", exc)
        _state["ready"] = True
    return _state["vecs"] is not None


def _semantic_scores(query: str) -> np.ndarray:
    """Cosine similarity of the query to every knowledge-base entry."""
    n = len(KNOWLEDGE_BASE)
    scores = np.zeros(n, dtype="float32")
    if not _ensure_embeddings():
        return scores
    q = _state["embedder"].encode([query], convert_to_numpy=True, normalize_embeddings=True).astype("float32")
    index = _state["index"]
    if index is not None:
        sims, ids = index.search(q, n)
        for s, i in zip(sims[0], ids[0]):
            if i >= 0:
                scores[i] = s
    else:
        scores = _state["vecs"] @ q[0]
    return scores


# ---------------------------------------------------------------------------
# Alert facts + retrieval
# ---------------------------------------------------------------------------
def _clean_evidence(text: str) -> str:
    return re.sub(r"^\s*\[[A-Za-z ]+\]\s*", "", text).strip()[:240]  # drop the "[Rule]" / "[ML]" prefix


def _facts(alert: dict) -> dict:
    try:
        conf = float(alert.get("confidence") or 0)
    except (TypeError, ValueError):
        conf = 0.0
    if conf <= 1.0:
        conf *= 100

    evidence: list[str] = []
    for e in alert.get("evidence") or []:
        if isinstance(e, str) and e.strip():
            cleaned = _clean_evidence(e)
            if cleaned and cleaned not in evidence:
                evidence.append(cleaned)

    return {
        "type": str(alert.get("type") or "Unknown"),
        "source": alert.get("source") or None,
        "target": alert.get("target") or None,
        "confidence": int(round(min(max(conf, 0), 100))),
        "evidence": evidence[:5],
    }


def retrieve_context(alert: dict, top_k: int = 2) -> list[dict]:
    """
    Knowledge-base entries most relevant to this alert, best first.
    Semantic similarity (FAISS) decides, and entries that match the alert's
    threat type (MITRE id or keywords) are boosted so the right one is first.
    Returns [] when nothing relevant exists (e.g. a generic "Anomaly").
    """
    facts = _facts(alert)
    canon = _canonical_type(facts["type"])
    hints = TYPE_HINTS.get(canon) if canon else None

    query = f"{facts['type']} attack. " + " ".join(facts["evidence"])
    sem = _semantic_scores(query)

    scored = []
    for i, entry in enumerate(KNOWLEDGE_BASE):
        score, matched = float(sem[i]), False
        if hints:
            if str(entry.get("mitre_id", "")).strip() in hints["mitre"]:
                score += 3.0
                matched = True
            blob = f"{entry.get('text', '')} {entry.get('mitre_name', '')}".lower()
            hits = sum(1 for kw in hints["keywords"] if kw in blob)
            if hits:
                score += 0.5 * min(hits, 3)
                matched = True
        scored.append((score, matched, float(sem[i]), entry))
    scored.sort(key=lambda s: s[0], reverse=True)

    if not scored:
        return []
    best = scored[0]
    # a known type needs a real match; an unknown type needs a clearly similar entry
    if not (best[1] or (canon is None and best[2] >= 0.35)):
        return []

    picked = [best[3]]
    for score, matched, sim, entry in scored[1:top_k]:
        if matched or sim >= 0.45:
            picked.append(entry)
    return picked


# ---------------------------------------------------------------------------
# Template fallback (uses the real alert facts too)
# ---------------------------------------------------------------------------
def _template(facts: dict, entries: list[dict], canon: str | None) -> tuple[str, str]:
    src = facts["source"] or "an unidentified host"
    dst = facts["target"] or "multiple destinations"
    hints = TYPE_HINTS.get(canon) if canon else None

    if hints:
        sentence = hints["template"].format(src=src, dst=dst, conf=facts["confidence"])
    else:
        sentence = f"{src} triggered a {facts['type']} detection involving {dst} (confidence {facts['confidence']}%)."

    parts = [sentence]
    if facts["evidence"]:
        parts.append(f"Evidence: {facts['evidence'][0].rstrip('.')}.")
    if entries:
        parts.append(str(entries[0].get("text", "")).strip()[:330])

    focus = facts["target"] if canon == "DDoS" else facts["source"]
    base = str(entries[0].get("recommended_action", "")).strip() if entries else ""
    if not base:
        base = "Review the host's recent activity, compare it with what is normal for it, and escalate if the pattern continues."
    action = (f"Focus on {focus}. " if focus else "") + base.rstrip(".") + ". " + READ_ONLY_NOTE

    return " ".join(p for p in parts if p)[:MAX_EXPLANATION_CHARS], action[:MAX_ACTION_CHARS + 120]


# ---------------------------------------------------------------------------
# Ollama
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "You are the analyst assistant inside VYUH, a passive, read-only network threat detector "
    "for critical infrastructure.\n"
    "Rules:\n"
    "- Use ONLY the alert facts and reference notes you are given. Never invent IP addresses, "
    "ports, numbers, domains or events.\n"
    "- VYUH cannot block, probe or change anything. Never say VYUH blocked or will block something. "
    "Response actions are taken by a human analyst through a separate channel.\n"
    "- Write plain English for a security analyst and be specific to this alert.\n"
    '- Reply with JSON only, exactly: {"explanation": "...", "recommended_action": "..."}\n'
    "- explanation: 2 to 3 sentences. Say what was seen (use the IP addresses and the confidence) "
    "and why it matters. Do NOT repeat the recommended action here.\n"
    "- recommended_action: 1 to 2 sentences of concrete steps for the analyst."
)


def _user_prompt(facts: dict, entries: list[dict]) -> str:
    lines = [
        "ALERT FACTS",
        f"Threat type: {facts['type']}",
        f"Source: {facts['source'] or 'none (many sources)'}",
        f"Target: {facts['target'] or 'none (many targets)'}",
        f"Confidence: {facts['confidence']}%",
        "Evidence:",
    ]
    lines += [f"- {e}" for e in facts["evidence"]] or ["- (none provided)"]
    if entries:
        lines += ["", "REFERENCE NOTES (from the knowledge base)"]
        for e in entries:
            lines.append(f"- {e.get('mitre_id', '')} ({e.get('mitre_name', '')}): {e.get('text', '')}")
            lines.append(f"  Typical analyst step: {e.get('recommended_action', '')}")
    return "\n".join(lines)


_model_lock = threading.Lock()
_resolved_model: str | None = None


def _resolve_model() -> str:
    """The configured model if it is pulled, else another pulled model of the same family."""
    global _resolved_model
    if _resolved_model:
        return _resolved_model
    with _model_lock:
        if _resolved_model:
            return _resolved_model
        resp = requests.get(f"{OLLAMA_URL}/api/tags", timeout=5)
        resp.raise_for_status()
        names = [m.get("name") for m in resp.json().get("models", []) if m.get("name")]

        choice = None
        for candidate in (OLLAMA_MODEL, f"{OLLAMA_MODEL}:latest"):
            if candidate in names:
                choice = candidate
                break
        if choice is None:
            family = OLLAMA_MODEL.split(":")[0]
            same = [n for n in names if n.split(":")[0] == family]
            choice = same[0] if same else None
        if choice is None:
            raise LookupError(f"model '{OLLAMA_MODEL}' is not pulled; run: ollama pull {OLLAMA_MODEL}")
        _resolved_model = choice
        return choice


def _ollama_chat(system: str, user: str) -> tuple[str, str]:
    model = _resolve_model()
    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "keep_alive": OLLAMA_KEEP_ALIVE,
        "options": {"temperature": 0.2, "num_predict": 300, "num_ctx": 2048},
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    resp = requests.post(f"{OLLAMA_URL}/api/chat", json=payload, timeout=OLLAMA_TIMEOUT)
    resp.raise_for_status()
    return (resp.json().get("message") or {}).get("content", ""), model


def _as_text(value) -> str:
    if isinstance(value, list):
        value = " ".join(str(v) for v in value)
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _parse_llm(text: str) -> dict | None:
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    try:
        obj = json.loads(text)
    except ValueError:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            return {"explanation": text} if len(text) >= 20 else None  # plain-text answer: use it as the explanation
        try:
            obj = json.loads(m.group(0))
        except ValueError:
            return None
    return obj if isinstance(obj, dict) else None


# a brief that claims VYUH itself blocked/isolated something contradicts the passive design
_BAD_CLAIM = re.compile(
    r"\b(vyuh|the system|this system)\b[^.]{0,60}\b(has blocked|blocked|isolated|quarantined|will block|will isolate)\b",
    re.I,
)


def _ask_llm(facts: dict, entries: list[dict]) -> tuple[dict, str]:
    raw, model = _ollama_chat(SYSTEM_PROMPT, _user_prompt(facts, entries))
    obj = _parse_llm(raw)
    if obj is None:
        raise ValueError("model did not return a usable answer")

    out = {}
    for field, limit in (("explanation", MAX_EXPLANATION_CHARS), ("recommended_action", MAX_ACTION_CHARS)):
        text = _as_text(obj.get(field))
        out[field] = text[:limit] if len(text) >= 20 and not _BAD_CLAIM.search(text) else None
    return out, model


def _llm_error_text(exc: Exception) -> str:
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "Ollama is not running (open the Ollama app or run: ollama serve)"
    if isinstance(exc, requests.exceptions.Timeout):
        return f"Ollama timed out after {OLLAMA_TIMEOUT:.0f}s (the first call loads the model; try again)"
    if isinstance(exc, requests.exceptions.HTTPError):
        code = exc.response.status_code if exc.response is not None else "?"
        if code == 404:
            return f"model '{OLLAMA_MODEL}' not found; run: ollama pull {OLLAMA_MODEL}"
        return f"Ollama returned HTTP {code}"
    if isinstance(exc, LookupError):
        return str(exc)
    return f"{type(exc).__name__}: {exc}"


# ---------------------------------------------------------------------------
# Cache (the same alert explained twice is instant)
# ---------------------------------------------------------------------------
_cache: dict[str, dict] = {}
_cache_lock = threading.Lock()
_CACHE_MAX = 200


def _cache_key(facts: dict) -> str:
    return hashlib.sha1(json.dumps(facts, sort_keys=True).encode("utf-8")).hexdigest()


def _cache_put(key: str, value: dict) -> None:
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX:
            _cache.pop(next(iter(_cache)))
        _cache[key] = value


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------
def explain_alert(alert: dict) -> dict:
    """
    Main entry point (called by main.py). Returns:
        {
            "explanation": str,
            "mitre_id": str,            # "N/A" when no technique applies
            "mitre_name": str,
            "recommended_action": str,
            "source": "ollama" | "template",
            "llm_status": str,          # "ok" or why the template was used
            "model": str | None,
            "retrieved": [mitre ids of the knowledge-base entries used],
            "latency_ms": int,
            "cached": bool,
        }
    """
    t0 = time.perf_counter()
    facts = _facts(alert)

    ck = _cache_key(facts)
    with _cache_lock:
        hit = _cache.get(ck)
    if hit:
        return {**hit, "cached": True}

    canon = _canonical_type(facts["type"])
    try:
        entries = retrieve_context(alert)
    except Exception as exc:  # retrieval must never break the dashboard either
        log.warning("retrieval failed: %s", exc)
        entries = []

    # a MITRE tag is only shown for a recognised threat type (never a guess)
    primary = entries[0] if (entries and canon and TYPE_HINTS[canon]["mitre"]) else None

    explanation, action = _template(facts, entries, canon)
    source, status, model = "template", "ok", None

    try:
        llm, model = _ask_llm(facts, entries)
        if llm["explanation"] or llm["recommended_action"]:
            explanation = llm["explanation"] or explanation
            action = llm["recommended_action"] or action
            source = "ollama"
        else:
            status = "model answer was unusable, template used"
    except Exception as exc:  # never let the LLM break the dashboard
        status = _llm_error_text(exc)
        log.warning("LLM unavailable: %s", status)

    result = {
        "explanation": explanation,
        "mitre_id": (primary.get("mitre_id") if primary else None) or "N/A",
        "mitre_name": (primary.get("mitre_name") if primary else None) or "N/A",
        "recommended_action": action,
        "source": source,
        "llm_status": "ok" if source == "ollama" else status,
        "model": model if source == "ollama" else None,
        "retrieved": [e.get("mitre_id") for e in entries],
        "latency_ms": int((time.perf_counter() - t0) * 1000),
        "cached": False,
    }
    if source == "ollama":  # cache only real LLM answers, so a later retry can still reach the LLM
        _cache_put(ck, result)
    return result


def warmup() -> dict:
    """Optional: load the embedder and the LLM ahead of the first request (e.g. before a demo)."""
    ok_embed = _ensure_embeddings()
    try:
        _ollama_chat("Reply with the single word: ok", "ok")
        llm = "ready"
    except Exception as exc:
        llm = _llm_error_text(exc)
    return {"embeddings": ok_embed, "llm": llm}


# ---------------------------------------------------------------------------
# Self-test:  python rag_engine.py [PortScan DDoS ...]
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    samples = {
        "PortScan": {"type": "PortScan", "source": "10.0.0.66", "target": "10.0.0.10", "confidence": 0.99,
                     "evidence": ["10.0.0.66 touched 60 distinct ports on 10.0.0.10"]},
        "DDoS": {"type": "DDoS", "target": "192.168.1.10", "confidence": 0.99,
                 "evidence": ["192.168.1.10 received connections from 200 distinct sources"]},
        "C2Beaconing": {"type": "C2Beaconing", "source": "10.0.0.66", "target": "203.0.113.10", "confidence": 0.95,
                        "evidence": ["10.0.0.66 contacted 203.0.113.10 12 times at ~10.0s intervals (very regular)"]},
        "DGA": {"type": "DGA", "source": "192.168.1.40", "confidence": 0.9,
                "evidence": ["192.168.1.40 contacted 40 distinct DNS destinations, each only 1-2 times"]},
        "DNSTunneling": {"type": "DNSTunneling", "source": "192.168.1.50", "target": "203.0.113.53", "confidence": 0.9,
                         "evidence": ["192.168.1.50 sent 25 DNS flows averaging 1900 bytes each"]},
        "Exfiltration": {"type": "Exfiltration", "source": "10.0.0.66", "target": "203.0.113.10", "confidence": 0.95,
                         "evidence": ["10.0.0.66 sent 18,400,000 bytes out, 3.1 std devs above average"]},
        "Anomaly": {"type": "Anomaly", "source": "192.168.1.77", "confidence": 0.7,
                    "evidence": ["[Anomaly] 192.168.1.77: 80% of its flows look statistically abnormal"]},
    }
    for name in (sys.argv[1:] or ["PortScan"]):
        print(f"\n=== {name} ===")
        sample = samples.get(name, {"type": name, "source": "10.0.0.5", "confidence": 0.8})
        print(json.dumps(explain_alert(sample), indent=2, ensure_ascii=False))