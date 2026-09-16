"""
MOSAIC Single-Agent Baseline
==============================
One LLM call receives the full evidence artefact list and returns a structured
forensic report. No UQ engine, no active probing, no cross-modal gate, no RAG.
Confidence is self-reported by the LLM (known to be poorly calibrated).

Run standalone:
    python baseline_single_agent.py --dataset africanfalls_insider --model deepseek-r1:14b

Or imported by experiment_runner_v1.py via run_pipeline_direct(..., is_baseline=True).
"""
from __future__ import annotations
import argparse
import asyncio
import json
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

SYSTEM_PROMPT = """You are a forensic analyst. Analyse the evidence artefacts provided and produce a structured forensic report.

Rules:
- Only assert what the evidence directly supports
- State confidence explicitly (0.0 to 1.0)
- Be specific about mechanism, not vague

Output ONLY valid JSON (no markdown, no preamble) with EXACTLY these keys:
{
  "executive_summary": "2-3 sentence plain-English summary of the investigation",
  "primary_hypothesis": "One sentence: the primary mechanism identified and supporting artefacts",
  "key_findings": ["Finding 1 — evidence basis", "Finding 2 — evidence basis"],
  "options": {"temperature": 0.1, "num_predict": 800},
  "timeline": ["T0: event", "T1: event"],
  "applicable_statutes_summary": ["Statute name: elements met"],
  "limitations": ["What cannot be determined from available evidence"],
  "confidence": 0.0
}"""


def call_ollama(model: str, prompt: str, timeout: int = 120) -> str:
    """Direct Ollama API call — no LangChain dependency."""
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.1, "num_predict": 1500}
    }).encode()

    req = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=payload, method="POST"
    )
    req.add_header("Content-Type", "application/json")

    with urllib.request.urlopen(req, timeout=300) as resp:
        result = json.loads(resp.read())
    return result.get("response", "")


def parse_llm_json(text: str) -> dict:
    """Extract JSON from LLM response, stripping any markdown fences."""
    text = text.strip()
    # Strip code fences
    if "```" in text:
        parts = text.split("```")
        for p in parts:
            p = p.strip()
            if p.startswith("json"):
                p = p[4:].strip()
            if p.startswith("{"):
                text = p
                break
    # Find first { ... }
    start = text.find("{")
    end = text.rfind("}") + 1
    if start >= 0 and end > start:
        text = text[start:end]
    return json.loads(text)


async def run_baseline(dataset_key: str, model: str) -> dict:
    """Run single-agent baseline on a dataset."""
    from synthetic_evidence import get_artefacts_for_dataset, get_ground_truth

    arts = get_artefacts_for_dataset(dataset_key)
    gt = get_ground_truth(dataset_key)

    # Build evidence context (same as what the full pipeline gets)
    evidence_lines = []
    for i, a in enumerate(arts):
        evidence_lines.append(
            f"[{i+1}] {a['tool']} ({a['modality']}): {a['description']}"
            f"\n    Tags: {', '.join(a['tags'])}"
        )
    evidence_ctx = "\n".join(evidence_lines)

    case_descriptions = {
        "africanfalls_insider":
            "Linux workstation, user Ann, suspected insider data exfiltration, UAE jurisdiction",
        "africanfalls_insider_degraded":
            "Linux workstation, user Ann, disk+logs only (no network capture), UAE jurisdiction",
        "africanfalls_ransomware":
            "Windows endpoint ransomware attack, RDP compromise suspected, UAE jurisdiction",
        "lone_wolf":
            "Extremism investigation, encrypted communications, UAE jurisdiction",
    }
    case_desc = case_descriptions.get(dataset_key, dataset_key)

    user_prompt = (
        f"Case: {case_desc}\n\n"
        f"Evidence ({len(arts)} artefacts):\n{evidence_ctx}\n\n"
        f"Produce the forensic report JSON."
    )
    full_prompt = f"SYSTEM:\n{SYSTEM_PROMPT}\n\nUSER:\n{user_prompt}"

    start = time.perf_counter()
    try:
        raw = call_ollama(model, full_prompt)
        content = parse_llm_json(raw)
        elapsed = round(time.perf_counter() - start, 2)
        success = True
        error = None
    except Exception as e:
        elapsed = round(time.perf_counter() - start, 2)
        content = {
            "executive_summary": f"LLM call failed: {e}",
            "primary_hypothesis": "",
            "key_findings": [],
            "timeline": [],
            "applicable_statutes_summary": [],
            "limitations": ["LLM call failed"],
            "confidence": 0.0,
        }
        success = False
        error = str(e)

    # Score against ground truth
    keywords = gt.get("keywords", [])
    fragment = gt.get("correct_fragment", "")
    full_text = json.dumps(content).lower()
    primary = content.get("primary_hypothesis", "").lower()

    keywords_hit = [k for k in keywords if k.lower() in full_text]
    primary_ok = fragment.lower() in primary if fragment else False
    kw_score = len(keywords_hit) / max(len(keywords), 1)
    gt_accuracy = (kw_score * 0.6) + (float(primary_ok) * 0.4)

    # Hypothesis P/R/F1 (binary: did we get the mechanism?)
    findings = content.get("key_findings", [])
    tp = sum(1 for f in findings if fragment.lower()
             in str(f).lower()) if fragment else 0
    fp = len(findings) - tp
    fn = 1 - min(tp, 1)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 1e-9)

    # Self-reported confidence (calibration check)
    self_conf = float(content.get("confidence", 0.5))

    return {
        "success": success,
        "is_baseline": True,
        "dataset": dataset_key,
        "model": model,
        "elapsed_seconds": elapsed,
        "error": error,
        # Metrics
        "compound_confidence": self_conf,  # self-reported — not deterministic
        "confidence_class": "SELF_REPORTED",
        "gt_accuracy": round(gt_accuracy, 4),
        "primary_hypothesis_correct": primary_ok,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "keyword_coverage": round(kw_score, 4),
        "keywords_hit": keywords_hit,
        "statute_count": len(content.get("applicable_statutes_summary", [])),
        "statute_precision_at_5": 0.0,  # no RAG, not scored
        "hypothesis_count": 1 if content.get("primary_hypothesis") else 0,
        "artefact_count": len(arts),
        "probe_iterations": 0,
        # Raw output for inspection
        "llm_output": content,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MOSAIC single-agent baseline")
    parser.add_argument("--dataset", default="africanfalls_insider",
                        choices=["africanfalls_insider", "africanfalls_ransomware",
                                 "africanfalls_insider_degraded", "lone_wolf"])
    parser.add_argument("--model", default="deepseek-r1:14b")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    print(f"\n{'='*55}")
    print(f"Single-Agent Baseline: {args.model}")
    print(f"Dataset: {args.dataset} | N={args.runs}")
    print(f"{'='*55}\n")

    results = []
    for i in range(args.runs):
        print(f"Run {i+1}/{args.runs}...", end=" ", flush=True)
        r = asyncio.run(run_baseline(args.dataset, args.model))
        results.append(r)
        status = "✓" if r["success"] else "✗"
        print(f"{status} conf(self)={r['compound_confidence']:.2f} "
              f"gt={r['gt_accuracy']:.3f} f1={r['f1']:.3f} t={r['elapsed_seconds']}s")
        if r.get("error"):
            print(f"  Error: {r['error']}")

    # Summary
    successful = [r for r in results if r["success"]]
    if successful:
        import statistics
        print(f"\n{'='*55}")
        print(f"BASELINE SUMMARY ({len(successful)}/{args.runs} successful)")
        for metric, key in [("GT Accuracy", "gt_accuracy"), ("F1", "f1"),
                            ("Self-Conf", "compound_confidence"), ("Time", "elapsed_seconds")]:
            vals = [r[key] for r in successful]
            mu = statistics.mean(vals)
            std = statistics.stdev(vals) if len(vals) > 1 else 0.0
            print(f"  {metric:15s}: {mu:.4f} ± {std:.4f}")

    # Save
    out_path = Path(__file__).parent / "results" / \
        f"baseline_{args.dataset}_{args.model.replace(':', '_')}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps({"runs": results}, indent=2, default=str))
    print(f"\nSaved: {out_path}")
