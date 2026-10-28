"""
NetGraph Sentinel — Phase 3/4: Detector (combines everything)

Runs ALL FOUR layers on flow data:
    1. Graph engine  (Phase 2 — shape-based)
    2. Rules         (fast threshold checks)
    3. Random Forest (trained ML classifier)
    4. Isolation Forest (unsupervised anomaly detection)

Then combines them: when multiple layers flag the same
(threat type, source/target), confidence goes up.

PHASE 1 addition: MITRE tactic mapping + campaign severity helpers
(pure functions, see the block above the __main__ section).
"""

import sys
from collections import defaultdict

import joblib
import pandas as pd

from flow_parser import load_and_normalize
from graph_engine import build_graph, get_graph_anomalies
from rules import get_rule_alerts
from features import extract_features

RF_MODEL_PATH = "../models/random_forest.pkl"
RF_ENCODER_PATH = "../models/label_encoder.pkl"
ANOMALY_MODEL_PATH = "../models/isolation_forest.pkl"

ML_MIN_FLOWS_PER_SOURCE = 3


def run_ml_classifier(flows: pd.DataFrame) -> list[dict]:
    model = joblib.load(RF_MODEL_PATH)
    encoder = joblib.load(RF_ENCODER_PATH)

    X = extract_features(flows)
    preds = model.predict(X)
    probs = model.predict_proba(X)
    labels = encoder.inverse_transform(preds)

    scored = flows.copy()
    scored["predicted_label"] = labels
    scored["predicted_confidence"] = probs.max(axis=1)

    alerts = []
    attack_flows = scored[scored["predicted_label"] != "BENIGN"]
    for (src, label), group in attack_flows.groupby(["src_ip", "predicted_label"]):
        if len(group) < ML_MIN_FLOWS_PER_SOURCE:
            continue
        avg_conf = group["predicted_confidence"].mean()
        alerts.append({
            "type": label,
            "source": src,
            "evidence": f"[ML] Random Forest classified {len(group)} flows from {src} as {label}",
            "confidence": round(float(avg_conf), 2),
            "layer": "ml",
        })
    return alerts


def run_anomaly_detector(flows: pd.DataFrame) -> list[dict]:
    from anomaly import score_anomalies

    model = joblib.load(ANOMALY_MODEL_PATH)
    scored = score_anomalies(flows, model=model)

    alerts = []
    for src, group in scored.groupby("src_ip"):
        anomaly_rate = group["is_anomaly"].mean()
        if anomaly_rate >= 0.5 and len(group) >= 3:
            alerts.append({
                "type": "Anomaly",
                "source": src,
                "evidence": f"[Anomaly] {src}: {anomaly_rate:.0%} of its flows look statistically abnormal",
                "confidence": round(0.4 + anomaly_rate * 0.4, 2),
                "layer": "anomaly",
            })
    return alerts


def combine_alerts(all_alerts: list[dict]) -> list[dict]:
    groups = defaultdict(list)
    for alert in all_alerts:
        key = (alert["type"], alert.get("source"), alert.get("target"))
        groups[key].append(alert)

    combined = []
    for key, group in groups.items():
        threat_type, source, target = key
        layers = sorted(set(a["layer"] for a in group))
        base_confidence = max(a["confidence"] for a in group)
        boost = 0.05 * (len(layers) - 1)
        final_confidence = min(0.99, base_confidence + boost)

        combined.append({
            "type": threat_type,
            "source": source,
            "target": target,
            "layers_agreeing": layers,
            "confidence": round(final_confidence, 2),
            "evidence": [a["evidence"] for a in group],
        })

    combined.sort(key=lambda a: a["confidence"], reverse=True)
    return combined


def detect_flows(flows: pd.DataFrame) -> list[dict]:
    """
    Run the full detection pipeline on an already-loaded, already-
    normalized flows DataFrame (timestamps should already be parsed).
    This is what the live pipeline (Phase 4) calls repeatedly on
    accumulated flows.
    """
    all_alerts = []

    G = build_graph(flows)
    graph_alerts = get_graph_anomalies(G)
    for a in graph_alerts:
        a["layer"] = "graph"
    all_alerts += graph_alerts

    all_alerts += get_rule_alerts(flows)

    try:
        all_alerts += run_ml_classifier(flows)
    except FileNotFoundError:
        pass

    try:
        all_alerts += run_anomaly_detector(flows)
    except FileNotFoundError:
        pass

    return combine_alerts(all_alerts)


def detect(csv_path: str) -> list[dict]:
    """Convenience wrapper: load + normalize a CSV, then run detect_flows."""
    flows = load_and_normalize(csv_path)
    flows["timestamp"] = pd.to_datetime(
        flows["timestamp"], format="%d/%m/%Y %H:%M:%S", errors="coerce"
    )
    return detect_flows(flows)


# ===========================================================================
# PHASE 1: MITRE ATT&CK tactic mapping + campaign severity
# ===========================================================================
# threat_type -> (tactic name, tactic id)
TACTIC_MAP = {
    "PortScan": ("Reconnaissance", "TA0043"),
    "C2Beaconing": ("Command and Control", "TA0011"),
    "DGA": ("Command and Control", "TA0011"),
    "DNSTunneling": ("Command and Control", "TA0011"),
    "Exfiltration": ("Exfiltration", "TA0010"),
    "DDoS": ("Impact", "TA0040"),
}

_SEVERITY_LEVELS = ["low", "medium", "high", "critical"]


def tactic_for(threat_type: str) -> tuple[str, str] | None:
    """MITRE tactic (name, id) for a threat type, or None (e.g. generic 'Anomaly')."""
    return TACTIC_MAP.get(threat_type)


def campaign_severity(stages: list[dict]) -> str:
    """
    Base level from the strongest stage confidence, then raised by how many
    distinct tactics the same host has shown (2 tactics = +1, 3+ = critical).
    """
    if not stages:
        return "low"
    top = max(s["confidence"] for s in stages)
    level = 2 if top >= 0.90 else 1 if top >= 0.75 else 0
    n = len({s["tactic"] for s in stages})
    if n >= 3:
        level = 3
    elif n == 2:
        level = min(3, level + 1)
    return _SEVERITY_LEVELS[level]


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python detector.py <path-to-csv>")
        sys.exit(1)

    results = detect(sys.argv[1])
    print(f"\n=== {len(results)} final alerts ===\n")
    for r in results:
        print(f"[{r['type']}] confidence={r['confidence']} — source={r['source']} target={r['target']}")
        print(f"  Layers agreeing: {', '.join(r['layers_agreeing'])}")
        for e in r["evidence"]:
            print(f"  - {e}")
        print()