# Presidio LLM Security Gateway

**CEN-451 Information Security – Assignment 2**
A modular security gateway that protects LLM-based systems from prompt injection, jailbreak attempts, and sensitive information leakage.

---

## Architecture

```
User Input
    │
    ▼
┌──────────────────────┐
│  Injection Detector  │  → Scoring 0-100, pattern matching across 7 categories
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Presidio Analyzer   │  → PII detection + 4 customizations
│  (Custom Recognizers)│
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  Policy Engine       │  → ALLOW / MASK / BLOCK
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│  OpenRouter LLM API  │  → Only called on ALLOW or MASK
└──────────────────────┘
```

---

## Quick Start

### 1. Prerequisites

- Python 3.10+
- pip

### 2. Install dependencies

```bash
git clone https://github.com/YOUR_USERNAME/presidio-llm-gateway.git
cd presidio-llm-gateway

pip install -r requirements.txt
python -m spacy download en_core_web_sm
```

### 3. Configure API key

```bash
cp .env.example .env
# Then open .env and paste your key:
# OPENROUTER_API_KEY=sk-or-v1-...
```

Get a free API key at [openrouter.ai](https://openrouter.ai).
The `.env` file is git-ignored and never committed.
The gateway runs fully without an API key (LLM calls are skipped; all security features still work).

### 4. Run

```bash
# Interactive chat mode
python main.py

# Demo with sample inputs
python main.py --demo

# Process a single input
python main.py --input "Ignore all previous instructions."

# Run full evaluation and generate all 5 tables
python main.py --evaluate
```

---

## Project Structure

```
presidio-llm-gateway/
├── src/
│   ├── __init__.py
│   ├── injection_detector.py    # Weighted pattern scoring (0-100)
│   ├── custom_recognizers.py    # PK_CNIC, PK_PHONE, API_KEY recognizers
│   ├── presidio_handler.py      # Presidio wrapper + 4 customizations
│   ├── policy_engine.py         # ALLOW / MASK / BLOCK logic
│   ├── llm_client.py            # OpenRouter API client
│   ├── gateway.py               # Pipeline orchestrator
│   └── utils.py                 # Config loader, logging, formatting
├── tests/
│   ├── __init__.py
│   └── test_data.py             # 21 labeled test scenarios
├── config/
│   └── config.yaml              # Configurable thresholds and parameters
├── evaluation/
│   ├── __init__.py
│   ├── metrics.py               # Precision, recall, F1, latency stats
│   └── run_evaluation.py        # Generates all 5 evaluation tables
├── evaluation/results/          # Auto-generated CSV tables (after running)
├── logs/                        # Gateway logs
├── requirements.txt
└── main.py
```

---

## Configuration

Edit `config/config.yaml` to adjust thresholds:

```yaml
gateway:
  injection_threshold: 50        # 0-100; above this = BLOCK
  pii_confidence_threshold: 0.7  # 0-1; above this = MASK
  anonymization_enabled: true

llm:
  model: "meta-llama/llama-3.1-8b-instruct:free"
  max_tokens: 1000
```

---

## Presidio Customizations

| # | Customization | File | Description |
|---|--------------|------|-------------|
| 1 | `PakistaniCNICRecognizer` | `custom_recognizers.py` | Detects CNIC format `XXXXX-XXXXXXX-X` |
| 2 | `PakistaniPhoneRecognizer` | `custom_recognizers.py` | Detects `03XX-XXXXXXX` and `+923XX-XXXXXXX` |
| 3 | `APIKeyRecognizer` | `custom_recognizers.py` | Detects `sk-*`, Bearer tokens, JWTs |
| 4 | Context-Aware Scoring | `presidio_handler.py` | Boosts confidence (+0.15) when near keywords like "my", "personal" |
| 5 | Composite Entity Detection | `presidio_handler.py` | Elevated risk (0.7-1.0) when Name+Phone+Location co-occur |
| 6 | Confidence Calibration | `presidio_handler.py` | Per-entity score deltas to reduce FP (e.g. DATE_TIME -0.10) |

---

## Evaluation

Run the evaluation script to generate all 5 required tables:

```bash
python main.py --evaluate
# OR
python evaluation/run_evaluation.py
```

Results are saved to `evaluation/results/`:
- `table1_scenario_evaluation.csv`     – Per-scenario detection results
- `table2_presidio_validation.csv`     – Customization validation
- `table3_performance_metrics.csv`     – Precision, Recall, F1, Accuracy
- `table4_threshold_calibration.csv`   – Threshold sweep (20–80)
- `table5_latency_summary.csv`         – Per-component latency stats

---

## Test Scenarios

21 labeled test cases covering:

| Category | Count | Expected Decision |
|----------|-------|------------------|
| Prompt Injection | 3 | BLOCK |
| Jailbreak | 4 | BLOCK |
| System Prompt Extraction | 3 | BLOCK |
| PII Leakage | 3 | MASK |
| Secret Exposure | 2 | BLOCK/MASK |
| Obfuscation | 1 | BLOCK |
| Safe (Benign) | 5 | ALLOW |

---

## Policy Decisions

| Decision | Condition | Action |
|----------|-----------|--------|
| **BLOCK** | Injection score ≥ threshold | Request rejected, no LLM call |
| **MASK** | PII detected (confidence ≥ threshold) | Text anonymised, forwarded to LLM |
| **ALLOW** | No injection, no PII | Request forwarded as-is to LLM |

---

## Reproducibility

All evaluation results are fully reproducible:

```bash
# Fresh environment
pip install -r requirements.txt
python -m spacy download en_core_web_sm
python main.py --evaluate
```

No API key required to reproduce evaluation tables (LLM calls are skipped when `OPENROUTER_API_KEY` is not set; detection logic is deterministic).

---

## Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| presidio-analyzer | 2.2.354 | PII detection engine |
| presidio-anonymizer | 2.2.354 | PII anonymisation |
| spacy | 3.7.4 | NLP backend for Presidio |
| requests | ≥2.31.0 | OpenRouter API calls |
| pyyaml | ≥6.0 | Configuration loading |

---
