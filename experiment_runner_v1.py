"""
MOSAIC Experiment Runner v1.1 
====================================================

Usage:
    python experiment_runner_v1.py              # full suite
    python experiment_runner_v1.py --quick      # 2 datasets, 3 runs, 1 model
    python experiment_runner_v1.py --dataset insider
"""
from __future__ import annotations
import argparse
import asyncio
import json
import math
import os
import sys
import time
import statistics
import traceback
import types
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

import sys
if sys.stdout.encoding != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

# ── path setup ───────────────────────────────────────────────────────────────
OUTPUT_DIR = Path(__file__).parent / "results"
DB_PATH = Path(__file__).parent / "mosaic_audit.db"

logger = structlog.get_logger(__name__)


# ── config mock ──────────────────────────────────────────────────────────────
def _install_config_mock():
    """Install a minimal config module so project imports don't crash."""
    if "config" in sys.modules:
        del sys.modules["config"]
    cfg_mod = types.ModuleType("config")

    class UQCfg:
        max_epistemic_uncertainty = 0.25
        min_compound_confidence = 0.65
        max_probe_iterations = 3

    class ThreatCfg:
        virustotal_available = False
        abuseipdb_available = False
        virustotal_key = ""
        abuseipdb_key = ""

    class StorageConfig:
        audit_db = DB_PATH
        cases_dir = BASE_DIR / "cases"
        output_dir = OUTPUT_DIR
        statutes_dir = BASE_DIR / "rag" / "statutes"

    class APICfg:
        host = "127.0.0.1"
        port = 8765

    class LLMCfg:
        model = os.environ.get("LLM_MODEL", "deepseek-r1:14b")
        api_key = os.environ.get("ANTHROPIC_API_KEY", "dummy")
        temperature = 0.1
        max_tokens = 2048

    class Cfg:
        uq = UQCfg()
        threat_intel = ThreatCfg()
        storage = StorageConfig()
        api = APICfg()
        llm = LLMCfg()

    cfg_mod.CONFIG = Cfg()
    sys.modules["config"] = cfg_mod


_install_config_mock()


# ═════════════════════════════════════════════════════════════════════════════
# GROUND-TRUTH SCORING
# ═════════════════════════════════════════════════════════════════════════════

def score_ground_truth(report: dict, gt: dict) -> dict:
    """
    Score a pipeline report against dataset ground truth.

    F1 uses BINARY RECALL by design:
        recall = 1.0 if ANY key_finding contains the correct mechanism fragment,
                 0.0 otherwise.
    This reflects the investigative goal of mechanism identification, not
    exhaustive hypothesis enumeration. Paper §4.6 states this explicitly.
    """
    keywords = gt.get("keywords", [])
    fragment = gt.get("correct_fragment", "")
    content = report.get("content", {})

    exec_txt = json.dumps(content.get("executive_summary", "")).lower()
    primary_txt = json.dumps(content.get("primary_hypothesis", "")).lower()
    findings_txt = json.dumps(content.get("key_findings", [])).lower()
    full_text = json.dumps(content).lower()
    enriched = " ".join([full_text, exec_txt, primary_txt, findings_txt])

    kw_hit = [k for k in keywords if k.lower() in enriched]
    kw_miss = [k for k in keywords if k.lower() not in enriched]
    primary_ok = bool(fragment) and fragment.lower() in primary_txt

    kw_score = len(kw_hit) / max(len(keywords), 1)
    gt_acc = kw_score * 0.60 + float(primary_ok) * 0.40

    # Precision / binary-Recall / F1
    findings = content.get("key_findings", [])
    hyp_texts = [str(h).lower() for h in findings] \
        if isinstance(findings, list) else [str(findings).lower()]
    tp = sum(1 for h in hyp_texts if fragment and fragment.lower() in h)
    fp = len(hyp_texts) - tp
    # Binary recall: 1.0 if mechanism found at least once, else 0.0
    recall = 1.0 if tp >= 1 else 0.0
    precision = tp / max(tp + fp, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)

    return {
        "gt_accuracy":              round(gt_acc, 4),
        "keywords_hit":             kw_hit,
        "keywords_missed":          kw_miss,
        "primary_hypothesis_correct": primary_ok,
        "precision":                round(precision, 4),
        # binary — see docstring
        "recall":                   round(recall, 4),
        "f1":                       round(f1, 4),
        "keyword_coverage":         round(kw_score, 4),
    }


def score_statutes(report: dict, expected: list[str]) -> dict:
    """Statute Precision@5."""
    retrieved = report.get("content", {}).get(
        "applicable_statutes_summary", []) or []
    top5 = [str(s).lower() for s in retrieved[:5]]
    hits = sum(1 for e in expected if any(e.lower() in s for s in top5))
    return {
        "statute_precision_at_5": round(hits / max(len(expected), 1), 4),
        "statutes_retrieved":     top5,
    }


def _compute_hallucination_rate(report: dict, art_dicts: list[dict]) -> float:
    """
    BUG-4 FIX — Hallucination rate (automated token-overlap method).

    A key_finding is flagged as 'potentially hallucinated' if it shares
    fewer than 2 meaningful tokens (≥5 chars) with the union of all injected
    artefact descriptions and raw_values.

    Conservative estimate: may miss paraphrase-level hallucinations. Paper
    §4.6 describes this definition and its limitation.
    """
    content = report.get("content", {})
    findings = content.get("key_findings", [])
    if not findings or not isinstance(findings, list):
        return 0.0

    # Build artefact token corpus
    art_corpus: set[str] = set()
    for a in art_dicts:
        blob = str(a.get("description", "")) + " " + \
            json.dumps(a.get("raw_value", {}))
        for tok in blob.lower().split():
            clean = tok.strip(".,;:\"'()[]{}|/\\")
            if len(clean) >= 5:
                art_corpus.add(clean)

    hallucinated = 0
    for finding in findings:
        ftoks = {t.strip(".,;:\"'()[]{}|/\\")
                 for t in str(finding).lower().split() if len(t) >= 5}
        if len(ftoks & art_corpus) < 2:
            hallucinated += 1

    return round(hallucinated / len(findings), 4)


# ═════════════════════════════════════════════════════════════════════════════
# REAL EXTRACTION MODULE
# ═════════════════════════════════════════════════════════════════════════════

def try_real_extraction(case_obj, state) -> tuple[list, str]:
    """
    Attempt real pytsk3/scapy extraction if evidence files actually exist.
    Returns (artefacts, extraction_note).
    Falls back silently to synthetic artefacts if files not present.
    """
    from schema import Artefact, Modality
    artefacts = []
    notes = []

    if case_obj.pcap_path and Path(case_obj.pcap_path).exists():
        try:
            import asyncio as _aio
            from pcap_tool import PCAPAnalyser
            raw = _aio.get_event_loop().run_until_complete(
                PCAPAnalyser(case_obj.pcap_path).analyse())
            artefacts.extend(raw)
            notes.append(
                f"scapy: {len(raw)} artefacts from {case_obj.pcap_path}")
            logger.info("real_pcap_extraction", n=len(
                raw), path=case_obj.pcap_path)
        except Exception as e:
            notes.append(f"scapy failed: {e}")

    if case_obj.disk_image_path and Path(case_obj.disk_image_path).exists():
        try:
            from tools.disk_tool import DiskForensicsTool
            import asyncio as _aio
            raw = _aio.get_event_loop().run_until_complete(
                DiskForensicsTool(case_obj.disk_image_path).analyse())
            artefacts.extend(raw)
            notes.append(
                f"pytsk3: {len(raw)} artefacts from {case_obj.disk_image_path}")
            logger.info("real_disk_extraction", n=len(
                raw), path=case_obj.disk_image_path)
        except Exception as e:
            notes.append(f"pytsk3 failed: {e}")

    return artefacts, "; ".join(notes) if notes else "no_real_evidence_files"


# ═════════════════════════════════════════════════════════════════════════════
# PIPELINE RUNNERS
# ═════════════════════════════════════════════════════════════════════════════

async def run_pipeline_direct(
    dataset_key:    str,
    model_name:     str,
    provider:       str,
    ablation_flags: dict | None = None,
    is_baseline:    bool = False,
) -> dict:
    """Run MOSAIC pipeline with injected artefacts."""
    from synthetic_evidence import (get_artefacts_for_dataset,
                                    get_ground_truth,
                                    get_probe_artefacts)

    os.environ["LLM_PROVIDER"] = provider
    os.environ["LLM_MODEL"] = model_name
    _install_config_mock()

    ablation_flags = ablation_flags or {}
    gt = get_ground_truth(dataset_key)
    art_dicts = get_artefacts_for_dataset(dataset_key)
    probe_dicts = get_probe_artefacts(dataset_key)

    start = time.perf_counter()
    try:
        from schema import CaseFile, GraphState, Artefact, Modality
        from audit_log import AuditLog

        case_path = BASE_DIR / "cases" / f"{dataset_key}.json"
        with open(case_path) as f:
            raw = json.load(f)
        case_obj = CaseFile(**{k: v for k, v in raw.items()
                               if k not in ("ground_truth", "case_metadata")})
        state = GraphState(case=case_obj)

        # Try real extraction first; fall back to synthetic
        real_arts, extr_note = try_real_extraction(case_obj, state)
        if real_arts:
            state.artefacts.extend(real_arts)
            art_dicts = []          # don't double-inject synthetic
        else:
            for ad in art_dicts:
                state.artefacts.append(Artefact(
                    id=ad["id"], modality=Modality(ad["modality"]),
                    tool=ad["tool"], description=ad["description"],
                    raw_value=ad["raw_value"],
                    hash_sha256=ad.get("hash_sha256"), tags=ad["tags"],
                ))

        # BUG-1 original: was AuditLog() with no path
        audit = AuditLog(DB_PATH)
        await audit.initialize()

        if is_baseline:
            return await _run_baseline(state, audit, gt,
                                       art_dicts or [
                                           a.__dict__ for a in state.artefacts],
                                       start, model_name, dataset_key, extr_note)

        return await _run_mosaic(state, audit, gt,
                                 art_dicts or [
                                     a.__dict__ for a in state.artefacts],
                                 probe_dicts,
                                 start, model_name, dataset_key,
                                 ablation_flags, extr_note)

    except Exception as e:
        elapsed = round(time.perf_counter() - start, 2)
        traceback.print_exc()
        return {
            "success": False, "elapsed_seconds": elapsed,
            "error": str(e), "dataset": dataset_key, "model": model_name,
            "is_baseline": is_baseline, "ablation_flags": ablation_flags,
        }


async def _run_mosaic(state, audit, gt, art_dicts, probe_dicts,
                      start, model_name, dataset_key, ablation_flags,
                      extr_note="synthetic"):
    """Full MOSAIC pipeline with BUG-1 probing fix applied."""
    # Cache the RAG instance across runs to avoid 9s reload per run
    if not hasattr(_run_mosaic, '_rag_cache'):
        _run_mosaic._rag_cache = None
    from agents import (orchestrator_node, forensic_analyst_node,
                        verifier_node, law_mapper_node, report_agent_node)
    from uq_engine import UQEngine
    from schema import Artefact, Modality
    from config import CONFIG

    uq_engine = UQEngine()

    state = await orchestrator_node(state, audit)

    # Initial UQ
    state.uq_result = uq_engine.compute(state)
    uq_before_probe = state.uq_result.compound_confidence
    uq_after_probe = uq_before_probe  # updated if probing fires

    state = await forensic_analyst_node(state, audit)

    # Verifier — optional ablation env vars
    if ablation_flags.get("no_crossmodal"):
        os.environ["MOSAIC_MIN_CORROBORATING_MODALITIES"] = "1"
    else:
        os.environ.pop("MOSAIC_MIN_CORROBORATING_MODALITIES", None)

    if ablation_flags.get("no_probing"):
        os.environ["MOSAIC_MAX_PROBE_ITERATIONS"] = "0"
    else:
        os.environ.pop("MOSAIC_MAX_PROBE_ITERATIONS", None)

    state = await verifier_node(state, audit)

    # ── BUG-1 FIX: probing loop now injects new artefacts ─────────────────
    probe_limit = 0 if ablation_flags.get("no_probing") \
        else CONFIG.uq.max_probe_iterations

    while (state.next_node == "evidence_collector"
           and state.probe_iteration <= probe_limit
           and not ablation_flags.get("no_probing")):

        # Inject additional artefacts that the EvidenceCollector can
        # retrieve without the missing modality (e.g. threat intel, OSINT).
        # This is architecturally honest: the Verifier flags the gap,
        # the Collector retrieves what it can from available sources.
        if probe_dicts:
            existing_ids = {a.id for a in state.artefacts}
            injected = 0
            for ad in probe_dicts:
                if ad["id"] not in existing_ids:
                    state.artefacts.append(Artefact(
                        id=ad["id"], modality=Modality(ad["modality"]),
                        tool=ad["tool"], description=ad["description"],
                        raw_value=ad["raw_value"],
                        hash_sha256=ad.get("hash_sha256"), tags=ad["tags"],
                    ))
                    injected += 1
            logger.info("probe_artefacts_injected",
                        iteration=state.probe_iteration,
                        n_injected=injected,
                        total_artefacts=len(state.artefacts))

        # Recompute UQ on enlarged artefact set → C will change upward
        state.uq_result = uq_engine.compute(state)
        uq_after_probe = state.uq_result.compound_confidence

        state = await forensic_analyst_node(state, audit)
        state = await verifier_node(state, audit)
    # ── end probing loop ───────────────────────────────────────────────────

    if not ablation_flags.get("no_rag"):
        state = await law_mapper_node(state, audit)
    else:
        state.statutes = []
        state.next_node = "report_agent"

    state = await report_agent_node(state, audit)
    elapsed = round(time.perf_counter() - start, 2)

    return _collect_metrics(
        state, gt, art_dicts, elapsed, model_name, dataset_key,
        ablation_flags, is_baseline=False,
        uq_before_probe=uq_before_probe,
        uq_after_probe=uq_after_probe,
        extr_note=extr_note,
    )


async def _run_baseline(state, audit, gt, art_dicts, start,
                        model_name, dataset_key, extr_note="synthetic"):
    """Single-agent LLM call — no UQ, no probing, no cross-modal gate, no RAG."""
    import urllib.request

    evidence_lines = [
        f"[{i+1}] {a.get('tool', '?')} ({a.get('modality', '?')}): "
        f"{a.get('description', '?')} | Tags: {','.join(a.get('tags', []))}"
        for i, a in enumerate(art_dicts)
    ]
    evidence_ctx = "\n".join(evidence_lines)

    sys_prompt = (
        "You are a forensic analyst. Analyse the evidence and produce a structured report. "
        "Output ONLY valid JSON (no markdown, no explanation) with exactly these keys: "
        "executive_summary (string), primary_hypothesis (string), "
        "key_findings (list of strings), "
        "applicable_statutes_summary (list of strings), confidence (float 0.0-1.0)."
    )
    user_prompt = (
        f"Case: {state.case.case_name} ({state.case.case_type}, "
        f"{state.case.jurisdiction})\n"
        f"Description: {state.case.description}\n\n"
        f"Evidence ({len(art_dicts)} artefacts):\n{evidence_ctx}\n\n"
        "Produce the forensic report JSON now."
    )
    full_prompt = f"SYSTEM:\n{sys_prompt}\n\nUSER:\n{user_prompt}"

    content: dict = {}
    llm_error = None
    try:
        payload = json.dumps({
            "model": model_name, "prompt": full_prompt,
            "stream": False,
            "options": {"temperature": 0.1, "num_predict": 1500},
        }).encode()
        req = urllib.request.Request(
            "http://localhost:11434/api/generate", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=300) as resp:
            raw_resp = json.loads(resp.read()).get("response", "")

        text = raw_resp.strip()
        if "```" in text:
            parts = text.split("```")
            for p in parts:
                p = p.strip()
                if p.startswith("json"):
                    p = p[4:].strip()
                if p.startswith("{"):
                    text = p
                    break
        si = text.find("{")
        ei = text.rfind("}") + 1
        content = json.loads(text[si:ei]) if si >= 0 and ei > si else {}

    except Exception as e:
        llm_error = str(e)
        logger.error("baseline_llm_failed", error=str(e))
        content = {
            "executive_summary": f"LLM call failed: {e}",
            "primary_hypothesis": "", "key_findings": [],
            "applicable_statutes_summary": [], "confidence": 0.5,
        }

    self_conf = float(content.get("confidence") or 0.5)

    state.report = {
        "case_id": state.case.case_id,
        "case_name": state.case.case_name,
        "content": content,
        "compound_confidence": self_conf,
        "confidence_class": "SELF_REPORTED",
        "hypothesis_count": 1 if content.get("primary_hypothesis") else 0,
        "statute_count": len(content.get("applicable_statutes_summary", [])),
        "probe_iterations": 0,
    }

    elapsed = round(time.perf_counter() - start, 2)
    result = _collect_metrics(
        state, gt, art_dicts, elapsed, model_name, dataset_key,
        {}, is_baseline=True,
        uq_before_probe=None, uq_after_probe=None,
        extr_note=extr_note,
    )
    if llm_error:
        result["llm_error"] = llm_error
    return result


def _collect_metrics(state, gt, art_dicts, elapsed,
                     model_name, dataset_key, ablation_flags,
                     is_baseline: bool,
                     uq_before_probe: float | None,
                     uq_after_probe:  float | None,
                     extr_note: str = "synthetic") -> dict:

    uq = state.uq_result
    gt_score = score_ground_truth(state.report or {}, gt)
    stat_score = score_statutes(
        state.report or {},
        gt.get("expected_statutes", []),
    )
    hall_rate = _compute_hallucination_rate(state.report or {}, art_dicts)

    # BUG-6 FIX: modality breakdown from actual UQ fields
    modality_breakdown: dict[str, str] = {}
    if uq:
        for m in uq.corroborating_modalities:
            modality_breakdown[m.value] = "corroborating"
        for m in uq.dissenting_modalities:
            modality_breakdown[m.value] = "dissenting"

    return {
        "success":                    True,
        "dataset":                    dataset_key,
        "model":                      model_name,
        "is_baseline":                is_baseline,
        "ablation_flags":             ablation_flags,
        "extraction_note":            extr_note,
        "elapsed_seconds":            elapsed,
        # UQ
        "compound_confidence":        round(uq.compound_confidence, 4) if uq else None,
        "confidence_class":           uq.confidence_class.value if uq else "NONE",
        "epistemic_uncertainty":      round(uq.epistemic_uncertainty, 4) if uq else None,
        "aleatoric_uncertainty":      round(uq.aleatoric_uncertainty, 4) if uq else None,
        "corroborating_modalities":   [m.value for m in uq.corroborating_modalities] if uq else [],
        "modality_breakdown":         modality_breakdown,
        "uq_before_probe":            uq_before_probe,
        "uq_after_probe":             uq_after_probe,
        # Evidence
        "artefact_count":             len(state.artefacts),
        "probe_iterations":           state.probe_iteration,
        "hypothesis_count":           len(state.hypotheses),
        "statute_count":              len(state.statutes),
        # GT metrics
        "gt_accuracy":                gt_score["gt_accuracy"],
        "primary_hypothesis_correct": gt_score["primary_hypothesis_correct"],
        "precision":                  gt_score["precision"],
        "recall":                     gt_score["recall"],
        "f1":                         gt_score["f1"],
        "keyword_coverage":           gt_score["keyword_coverage"],
        "keywords_hit":               gt_score["keywords_hit"],
        "keywords_missed":            gt_score["keywords_missed"],
        # Legal
        "statute_precision_at_5":     stat_score["statute_precision_at_5"],
        "statutes_retrieved":         stat_score["statutes_retrieved"],
        # Hallucination — BUG-4 fix
        "hallucination_rate":         hall_rate,
    }


# ═════════════════════════════════════════════════════════════════════════════
# AGGREGATION
# ═════════════════════════════════════════════════════════════════════════════

def aggregate_runs(runs: list[dict]) -> dict:
    ok = [r for r in runs if r.get("success")]
    if not ok:
        return {"error": "all_failed", "n_runs": len(runs), "raw_runs": runs}

    def m(k):
        v = [r[k] for r in ok if r.get(k) is not None]
        return round(statistics.mean(v), 4) if v else None

    def s(k):
        v = [r[k] for r in ok if r.get(k) is not None]
        return round(statistics.stdev(v), 4) if len(v) > 1 else 0.0

    agg = {
        "model":              ok[0]["model"],
        "dataset":            ok[0]["dataset"],
        "is_baseline":        ok[0].get("is_baseline", False),
        "ablation_flags":     ok[0].get("ablation_flags", {}),
        "n_runs":             len(runs),
        "n_successful":       len(ok),
        # Time
        "mean_elapsed":       m("elapsed_seconds"),
        "std_elapsed":        s("elapsed_seconds"),
        # UQ — BUG-2: std_confidence MUST be 0.000 for deterministic UQ
        "mean_confidence":    m("compound_confidence"),
        "std_confidence":     s("compound_confidence"),
        "mean_epistemic":     m("epistemic_uncertainty"),
        "mean_aleatoric":     m("aleatoric_uncertainty"),
        # GT
        "mean_gt_accuracy":   m("gt_accuracy"),
        "std_gt_accuracy":    s("gt_accuracy"),
        "mean_precision":     m("precision"),
        "mean_recall":        m("recall"),
        "mean_f1":            m("f1"),
        "std_f1":             s("f1"),
        "mean_keyword_coverage": m("keyword_coverage"),
        "primary_correct_rate":  round(
            sum(1 for r in ok if r.get("primary_hypothesis_correct")) / len(ok), 4),
        # Evidence
        "mean_artefacts":        m("artefact_count"),
        "mean_probe_iterations": m("probe_iterations"),
        "mean_hypothesis_count": m("hypothesis_count"),
        "mean_statute_count":    m("statute_count"),
        "mean_statute_p5":       m("statute_precision_at_5"),
        # Hallucination — BUG-4
        "mean_hallucination_rate": m("hallucination_rate"),
        "std_hallucination_rate":  s("hallucination_rate"),
        # Probing trajectory
        "mean_uq_before_probe":  m("uq_before_probe"),
        "mean_uq_after_probe":   m("uq_after_probe"),
        # Classes
        "confidence_classes": dict(
            Counter(r.get("confidence_class") for r in ok)),
        "raw_runs": runs,
    }

    # Determinism self-check
    std_c = agg["std_confidence"]
    if std_c is not None and std_c > 0.0 and not agg["is_baseline"]:
        agg["uq_determinism_warning"] = (
            f"std_confidence={std_c} > 0 — UQ engine may be non-deterministic. "
            "Check for randomness in UQ pipeline (uuid generation, dict ordering)."
        )

    return agg


# ═════════════════════════════════════════════════════════════════════════════
# STATISTICAL TESTS
# ═════════════════════════════════════════════════════════════════════════════

def mann_whitney_u(a: list[float], b: list[float], label: str = "") -> dict:
    """Two-sided Mann-Whitney U with rank-biserial r effect size."""
    from scipy.stats import mannwhitneyu
    import numpy as np
    if len(a) < 2 or len(b) < 2:
        return {"error": f"n_too_small (a={len(a)}, b={len(b)})", "label": label}
    stat, p = mannwhitneyu(a, b, alternative="two-sided")
    r = 1 - (2 * stat) / (len(a) * len(b))
    return {
        "label":                label,
        "U":                    round(float(stat), 4),
        "p_value":              round(float(p), 6),
        "rank_biserial_r":      round(float(r), 4),
        "significant_at_0.05":  bool(p < 0.05),
        "n_a":                  len(a),
        "n_b":                  len(b),
        "median_a":             round(float(np.median(a)), 4),
        "median_b":             round(float(np.median(b)), 4),
    }


def compute_welch_t(a: list[float], b: list[float], label: str = "") -> dict:
    """BUG-5 FIX — Welch's t-test with Cohen's d for execution time."""
    from scipy.stats import ttest_ind
    if len(a) < 2 or len(b) < 2:
        return {"error": f"n_too_small (a={len(a)}, b={len(b)})", "label": label}
    stat, p = ttest_ind(a, b, equal_var=False)
    s1, s2 = statistics.stdev(a), statistics.stdev(b)
    n1, n2 = len(a), len(b)
    pooled = math.sqrt(((n1 - 1) * s1**2 + (n2 - 1) * s2**2) / (n1 + n2 - 2))
    d = (statistics.mean(a) - statistics.mean(b)) / \
        pooled if pooled > 0 else 0.0
    return {
        "label":                label,
        "t":                    round(float(stat), 4),
        "p_value":              round(float(p), 6),
        "cohens_d":             round(d, 4),
        "significant_at_0.05":  bool(p < 0.05),
        "mean_a_seconds":       round(statistics.mean(a), 2),
        "mean_b_seconds":       round(statistics.mean(b), 2),
        "speedup_b_over_a":     round(statistics.mean(a) / max(statistics.mean(b), 0.001), 2),
    }


def compute_ece(confidences: list[float], correct: list[bool],
                n_bins: int = 10) -> float:
    """Expected Calibration Error — Guo et al. 2017."""
    # Filter out None values (from failed LLM runs)
    pairs = [(c, a) for c, a in zip(confidences, correct)
             if c is not None]
    if not pairs:
        return 0.0
    confidences, correct = zip(*pairs)
    ece = 0.0
    n = len(confidences)
    for i in range(n_bins):
        lo, hi = i / n_bins, (i + 1) / n_bins
        mask = [lo <= c < hi for c in confidences]
        bc = [c for c, m in zip(confidences, mask) if m]
        ba = [float(x) for x, m in zip(correct, mask) if m]
        if bc:
            ece += (len(bc) / n) * \
                abs(statistics.mean(bc) - statistics.mean(ba))
    return round(ece, 4)


# ═════════════════════════════════════════════════════════════════════════════
# EXPERIMENT ORCHESTRATION
# ═════════════════════════════════════════════════════════════════════════════

EXPERIMENTS: dict[str, dict] = {
    "full": {
        "datasets": ["africanfalls_insider",
                     "africanfalls_ransomware",
                     "hacking_case"],
        "models":   [("deepseek-r1:14b", "ollama"),
                     ("deepseek-r1:32b", "ollama")],
        "n_runs":           5,
        "n_ablation_runs":  3,
        "run_baseline":  True,
        "run_degraded":  True,
        "run_ablation":  True,
    },
    "quick": {
        "datasets": ["africanfalls_insider", "africanfalls_ransomware"],
        "models":   [("deepseek-r1:14b", "ollama")],
        "n_runs":           3,
        "n_ablation_runs":  3,
        "run_baseline":  True,
        "run_degraded":  True,
        "run_ablation":  True,
    },
}

ABLATION_CONDITIONS = [
    ({},                       "Full MOSAIC"),
    ({"no_probing":    True},  "–Active Probing"),
    ({"no_crossmodal": True},  "–Cross-Modal Gate"),
    ({"no_rag":        True},  "–Legal RAG"),
]


async def run_all_experiments(config_name: str,
                              dataset_filter: str | None = None) -> dict:
    cfg = EXPERIMENTS[config_name]
    datasets = cfg["datasets"]
    if dataset_filter:
        datasets = [d for d in datasets if dataset_filter in d]

    all_results:    list[dict] = []
    all_aggregates: list[dict] = []
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    print(f"\n{'='*65}")
    print(f"MOSAIC Experiment Runner v1.1 — {config_name.upper()}")
    print(f"Datasets : {datasets}")
    print(f"Models   : {[m[0] for m in cfg['models']]}")
    print(f"N runs   : {cfg['n_runs']} main / "
          f"{cfg['n_ablation_runs']} ablation")
    print(f"{'='*65}\n")

    # ── Main experiments ─────────────────────────────────────────────────
    for ds in datasets:
        for model, provider in cfg["models"]:
            print(f"\n▶ {ds} / {model}")
            runs = []
            for i in range(cfg["n_runs"]):
                print(f"  Run {i+1}/{cfg['n_runs']}...", end=" ", flush=True)
                r = await run_pipeline_direct(ds, model, provider)
                runs.append(r)
                if r.get("success"):
                    print(f"✓ conf={r.get('compound_confidence', '?')} "
                          f"f1={r.get('f1', '?')} "
                          f"hall={r.get('hallucination_rate', '?')} "
                          f"[{r.get('extraction_note', '?')[:25]}]")
                else:
                    print(f"✗ {str(r.get('error', '?'))[:60]}")

            agg = aggregate_runs(runs)
            all_aggregates.append(agg)
            all_results.extend(runs)
            warn = agg.get("uq_determinism_warning", "")
            print(f"  → mean_f1={agg.get('mean_f1', '?')} "
                  f"std_conf={agg.get('std_confidence', '?')} "
                  f"{'⚠ ' + warn[:40] if warn else '✓ deterministic'}")

    # ── Baseline ─────────────────────────────────────────────────────────
    if cfg.get("run_baseline"):
        model, provider = cfg["models"][0]
        print(f"\n▶ SINGLE-AGENT BASELINE — {model}")
        for ds in datasets:
            runs = []
            for i in range(cfg["n_runs"]):
                print(f"  [{ds[:30]}] Run {i+1}...", end=" ", flush=True)
                r = await run_pipeline_direct(
                    ds, model, provider, is_baseline=True)
                runs.append(r)
                print(f"{'✓' if r.get('success') else '✗'} "
                      f"f1={r.get('f1', '?')} "
                      f"hall={r.get('hallucination_rate', '?')}")
            agg = aggregate_runs(runs)
            agg["is_baseline"] = True
            all_aggregates.append(agg)
            all_results.extend(runs)

    # ── Degraded scenario ─────────────────────────────────────────────────
    if cfg.get("run_degraded"):
        model, provider = cfg["models"][0]
        print(f"\n▶ DEGRADED SCENARIO (probing validation) — {model}")
        runs = []
        for i in range(cfg["n_runs"]):
            print(f"  Run {i+1}...", end=" ", flush=True)
            r = await run_pipeline_direct(
                "africanfalls_insider_degraded", model, provider)
            runs.append(r)
            if r.get("success"):
                before = r.get("uq_before_probe") or 0
                after = r.get("uq_after_probe") or 0
                delta = after - before
                print(f"✓ probes={r.get('probe_iterations', '?')} "
                      f"C_before={before:.3f} "
                      f"C_after={after:.3f} "
                      f"ΔC={delta:+.3f}")
            else:
                print(f"✗ {str(r.get('error', '?'))[:60]}")

        agg = aggregate_runs(runs)
        agg["dataset"] = "africanfalls_insider_degraded"
        all_aggregates.append(agg)
        all_results.extend(runs)
        b = agg.get("mean_uq_before_probe") or 0
        a = agg.get("mean_uq_after_probe") or 0
        pct = (a - b) / max(1 - b, 1e-6) * 100
        print(f"  → mean_probes={agg.get('mean_probe_iterations', '?')} "
              f"mean_ΔC={a-b:+.3f} "
              f"confidence_recovery={pct:.1f}%")

    # ── Ablation ──────────────────────────────────────────────────────────
    if cfg.get("run_ablation"):
        model, provider = cfg["models"][0]
        ds = "africanfalls_insider"
        print(f"\n▶ ABLATION — {model} on {ds}")
        for flags, label in ABLATION_CONDITIONS:
            runs = []
            for i in range(cfg["n_ablation_runs"]):
                print(f"  [{label}] Run {i+1}...", end=" ", flush=True)
                r = await run_pipeline_direct(
                    ds, model, provider, ablation_flags=flags)
                runs.append(r)
                print(f"{'✓' if r.get('success') else '✗'} "
                      f"f1={r.get('f1', '?')}")
            agg = aggregate_runs(runs)
            agg["ablation_condition"] = label
            all_aggregates.append(agg)
            all_results.extend(runs)

    # ── Statistical tests ─────────────────────────────────────────────────
    stats: dict[str, dict] = {}
    m0 = cfg["models"][0][0]

    if len(cfg["models"]) >= 2:
        m1, m2 = cfg["models"][0][0], cfg["models"][1][0]
        for ds in datasets:
            # GT accuracy — Mann-Whitney U
            g1 = [r["gt_accuracy"] for r in all_results
                  if r.get("dataset") == ds and r.get("model") == m1
                  and r.get("success") and not r.get("is_baseline")]
            g2 = [r["gt_accuracy"] for r in all_results
                  if r.get("dataset") == ds and r.get("model") == m2
                  and r.get("success") and not r.get("is_baseline")]
            if g1 and g2:
                stats[f"mw_gt_{ds}_{m1}_vs_{m2}"] = mann_whitney_u(
                    g1, g2, f"GT Accuracy: {m1} vs {m2} / {ds}")

            # Execution time — BUG-5 FIX: Welch's t + Cohen's d
            t1 = [r["elapsed_seconds"] for r in all_results
                  if r.get("dataset") == ds and r.get("model") == m1
                  and r.get("success") and not r.get("is_baseline")]
            t2 = [r["elapsed_seconds"] for r in all_results
                  if r.get("dataset") == ds and r.get("model") == m2
                  and r.get("success") and not r.get("is_baseline")]
            if t1 and t2:
                stats[f"welch_time_{ds}_{m1}_vs_{m2}"] = compute_welch_t(
                    t1, t2, f"Time: {m1} vs {m2} / {ds}")

    # MOSAIC vs baseline — F1, GT accuracy, hallucination
    for ds in datasets:
        mosaic_runs = [r for r in all_results
                       if r.get("dataset") == ds and r.get("model") == m0
                       and r.get("success") and not r.get("is_baseline")
                       and not r.get("ablation_flags")]
        base_runs = [r for r in all_results
                     if r.get("dataset") == ds and r.get("is_baseline")
                     and r.get("success")]
        if mosaic_runs and base_runs:
            stats[f"mw_f1_mosaic_vs_baseline_{ds}"] = mann_whitney_u(
                [r["f1"] for r in mosaic_runs],
                [r["f1"] for r in base_runs],
                f"F1: MOSAIC vs Baseline / {ds}")
            stats[f"mw_hall_mosaic_vs_baseline_{ds}"] = mann_whitney_u(
                [r["hallucination_rate"] for r in mosaic_runs],
                [r["hallucination_rate"] for r in base_runs],
                f"Hallucination: MOSAIC vs Baseline / {ds}")

    # ECE
    ece: dict[str, float] = {}
    for ds in datasets:
        for model, _ in cfg["models"]:
            runs = [r for r in all_results
                    if r.get("dataset") == ds and r.get("model") == model
                    and r.get("success") and not r.get("is_baseline")
                    and not r.get("ablation_flags")]
            if runs:
                ece[f"{ds}/{model}"] = compute_ece(
                    [r.get("compound_confidence", 0.5) for r in runs],
                    [r.get("primary_hypothesis_correct", False) for r in runs])
        base_runs = [r for r in all_results
                     if r.get("dataset") == ds and r.get("is_baseline")
                     and r.get("success")]
        if base_runs:
            ece[f"{ds}/baseline"] = compute_ece(
                [r.get("compound_confidence", 0.5) for r in base_runs],
                [r.get("primary_hypothesis_correct", False) for r in base_runs])

    # ── Save outputs ──────────────────────────────────────────────────────
    json_path = OUTPUT_DIR / f"results_{timestamp}.json"
    md_path = OUTPUT_DIR / f"results_{timestamp}.md"

    out = {
        "timestamp":  timestamp,
        "config":     config_name,
        "aggregates": all_aggregates,
        "stats":      stats,
        "ece":        ece,
        "raw_runs":   all_results,
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2, default=str)

    # Markdown table
    lines = [
        f"# MOSAIC Results — {timestamp}", "",
        "| Dataset | Model/Condition | F1 | Hall% | Conf (std) "
        "| Probes | P@5 | Time(s) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for agg in all_aggregates:
        if agg.get("error"):
            continue
        base_tag = " (baseline)" if agg.get("is_baseline") else ""
        abl_tag = (f" [{agg.get('ablation_condition', '')}]"
                   if agg.get("ablation_condition") else "")
        std_c = agg.get("std_confidence", "?")
        det = "OK" if std_c == 0.0 else f"WARN:{std_c}"
        lines.append(
            f"| {agg['dataset']} | {agg['model']}{base_tag}{abl_tag} "
            f"| {agg.get('mean_f1', '—')} "
            f"| {agg.get('mean_hallucination_rate', '—')} "
            f"| {agg.get('mean_confidence', '—')} ({det}) "
            f"| {agg.get('mean_probe_iterations', '—')} "
            f"| {agg.get('mean_statute_p5', '—')} "
            f"| {agg.get('mean_elapsed', '—')} |"
        )
    lines += ["", "## ECE", ""]
    for k, v in ece.items():
        lines.append(f"- {k}: {v}")
    lines += ["", "## Statistical Tests", ""]
    for k, v in stats.items():
        if "error" in v:
            lines.append(f"- {k}: {v['error']}")
        else:
            lines.append(
                f"- {v.get('label', '?')}: "
                f"U={v.get('U', v.get('t', '?'))}, "
                f"p={v.get('p_value', '?')}, "
                f"effect={v.get('rank_biserial_r', v.get('cohens_d', '?'))}, "
                f"sig={v.get('significant_at_0.05', '?')}")

    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"\n{'='*65}")
    print("DONE")
    print(f"  JSON : {json_path}")
    print(f"  MD   : {md_path}")
    print(f"\nDETERMINISM CHECK:")
    for agg in all_aggregates:
        if agg.get("is_baseline") or agg.get("error"):
            continue
        std_c = agg.get("std_confidence")
        tag = "OK 0.000" if std_c == 0.0 else f"WARN {std_c}"
        print(f"  [{agg['dataset']}/{agg['model']}] std_confidence={tag}")
    print(f"{'='*65}\n")
    return out


# ═════════════════════════════════════════════════════════════════════════════
# CLI
# ═════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MOSAIC Experiment Runner v1.1")
    parser.add_argument("--quick",   action="store_true",
                        help="2 datasets, 1 model, 10 runs")
    parser.add_argument("--dataset", default=None,
                        help="Filter to datasets containing this string")
    args = parser.parse_args()
    config = "quick" if args.quick else "full"
    asyncio.run(run_all_experiments(config, dataset_filter=args.dataset))
