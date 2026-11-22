"""Machine-learning detection with an Isolation Forest.

What it does
  Trains on the per-window feature vectors (Module 3) and scores each time window by how
  statistically unusual it is compared with the other windows of the SAME log. It needs no
  labelled data. It is never trained on single log lines.

Three safeguards against unreliable results (your spec: "avoid presenting unreliable predictions"):
  1. Small data: it will not run with fewer than `ml_min_active_windows` active windows.
  2. Only ACTIVE windows are used. Otherwise a log that is idle 90% of the time makes every
     busy minute look "anomalous".
  3. Materiality gate: an Isolation Forest ALWAYS flags a few windows, even in perfectly normal
     data. So a flagged window is only reported if at least one count feature is also far above
     typical (>= `ml_min_deviation` robust units, using the median and MAD, with a floor of one
     event). Normal logs therefore stay clean; a flagged window must be unusual in size, too.

The output is a STATISTICAL anomaly: it is not a probability of attack and carries no category."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.detection.common import Context, merge_windows
from app.detection.models import METHOD_ML, Detection
from app.features.feature_engineering import WINDOW_FEATURE_COLUMNS

RANDOM_STATE = 42
N_ESTIMATORS = 200
# Features measured in "number of things". Ratios and gaps are used by the model, but not by the gate.
COUNT_FEATURES = ["events", "failed_logins", "successful_logins", "unique_source_ips", "unique_usernames",
                  "unique_dest_ports", "http_requests", "http_4xx", "http_5xx", "max_events_per_ip"]
DOMINANT_IP_SHARE = 0.5


def _skipped(reason: str, **extra) -> tuple[list[Detection], dict]:
    return [], {"ran": False, "reason": reason, **extra}


def run_isolation_forest(ctx: Context) -> tuple[list[Detection], dict]:
    t = ctx.t
    if not ctx.features.capabilities["has_timestamps"]:
        return _skipped("The log has no usable timestamps, so activity cannot be grouped into time windows.")

    windows = ctx.features.window_features
    active = windows[windows["events"] > 0].reset_index(drop=True)
    if len(active) < t.ml_min_active_windows:
        return _skipped(
            f"Only {len(active)} active time windows; at least {t.ml_min_active_windows} are needed for a reliable "
            "statistical baseline. Rule-based detection was still applied.",
            windows_analyzed=len(active),
        )

    model = IsolationForest(n_estimators=N_ESTIMATORS, contamination=t.ml_contamination, random_state=RANDOM_STATE)
    model.fit(active[WINDOW_FEATURE_COLUMNS].to_numpy(dtype=float))
    flagged_by_model = model.predict(active[WINDOW_FEATURE_COLUMNS].to_numpy(dtype=float)) == -1
    scores = -model.score_samples(active[WINDOW_FEATURE_COLUMNS].to_numpy(dtype=float))   # higher = more unusual

    counts = active[COUNT_FEATURES].astype(float)
    typical = counts.median()
    scale = np.maximum(1.4826 * (counts - typical).abs().median(), 1.0)        # robust spread, at least 1 event
    deviation = (counts - typical) / scale
    reported = flagged_by_model & (deviation.max(axis=1).to_numpy() >= t.ml_min_deviation)

    status = {
        "ran": True,
        "reason": None,
        "windows_analyzed": int(len(active)),
        "windows_flagged_by_model": int(flagged_by_model.sum()),
        "windows_reported": int(reported.sum()),
        "contamination": t.ml_contamination,
        "min_deviation": t.ml_min_deviation,
        "features_used": WINDOW_FEATURE_COLUMNS,
    }

    detections = []
    for start, end in merge_windows(active.loc[reported, "window"], ctx.window_seconds):
        in_run = reported & (active["window"] >= start).to_numpy() & (active["window"] < end).to_numpy()
        detections.append(_to_detection(ctx, active, scores, deviation, typical, in_run, start, end))
    return detections, status


def _to_detection(ctx, active, scores, deviation, typical, in_run, start, end) -> Detection:
    rows = ctx.rows_in_range(None, start, end)
    top_ips = rows["source_ip"].value_counts()
    dominant = None
    if len(top_ips) and top_ips.iloc[0] >= DOMINANT_IP_SHARE * len(rows):
        dominant = str(top_ips.index[0])

    # Which features were most extreme, and by how much?
    peak = deviation[in_run].max()
    top = []
    for feature in peak.sort_values(ascending=False).index[:3]:
        if peak[feature] >= 3:
            top.append({"feature": feature, "value": float(active.loc[in_run, feature].max()),
                        "typical": float(typical[feature]), "deviation": round(float(peak[feature]), 1)})

    shown = rows[rows["source_ip"] == dominant] if dominant else rows
    detection = ctx.make_detection(
        method=METHOD_ML, rule_id="isolation_forest_window", source_ip=dominant, rows=shown,
        occurrences=len(rows), record_rows=rows,
        description=("Statistically unusual activity between "
                     f"{start:%Y-%m-%d %H:%M:%S} and {end:%Y-%m-%d %H:%M:%S}: "
                     + "; ".join(f"{m['feature']} up to {m['value']:g} (typical {m['typical']:g})" for m in top)
                     + ". This is a statistical outlier, not a confirmed attack."),
        metrics={"anomaly_score": round(float(scores[in_run].max()), 3), "windows_flagged": int(in_run.sum()),
                 "top_deviations": top, "min_deviation": ctx.t.ml_min_deviation},
    )
    detection.start, detection.end = f"{start:%Y-%m-%d %H:%M:%S}", f"{end:%Y-%m-%d %H:%M:%S}"
    return detection
