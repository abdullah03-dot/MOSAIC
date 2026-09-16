# MOSAIC — Multi-Agent Open-Source AI for Criminal Investigation

Supplementary code for: "MOSAIC: A Multi-Agent Framework for Autonomous 
Digital Forensics with Uncertainty-Quantified Evidence Fusion and Legal 
Statute Mapping"

## Setup
```bash
conda activate mosaic
pip install -r requirements.txt
```

## Run experiments
```bash
# Requires Ollama running: ollama serve
python experiment_runner_v1.py --quick   # fast test
python experiment_runner_v1.py           # full suite
```

## Generate figures
```bash
python generate_figures.py
```

## Results
Pre-computed results from the paper are in `results/`.

## Cases
Forensic challenge case definitions are in `cases/`.
Evidence artefacts are structured stubs derived from published NIST CFReDS 
ground truth (cfreds.nist.gov).