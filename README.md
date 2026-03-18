# Aletheia

### Adversary Campaign Correlation & Attribution Engine

---

## Overview

**Aletheia** is a graph-based threat intelligence system designed to transform raw Indicators of Compromise (IOCs) into structured adversary campaigns using deterministic infrastructure correlation and explainable evidence modeling.

The system ingests fragmented threat indicators, enriches them with infrastructure intelligence, constructs a graph representation, and identifies adversary campaigns through connectivity and evidence-driven scoring.

---

## Problem Statement

Modern threat intelligence is highly fragmented. Indicators such as domains, IPs, and URLs are often analyzed in isolation, making it difficult to:

* Identify coordinated adversary campaigns
* Understand infrastructure reuse
* Perform reliable attribution
* Generate actionable intelligence

---

## Solution

Aletheia addresses this by:

* Modeling threat infrastructure as a graph
* Correlating indicators based on shared infrastructure
* Clustering related indicators into campaigns
* Generating explainable evidence signals
* Producing deterministic campaign confidence scores

---

## Core Capabilities

* IOC ingestion from multiple threat intelligence sources
* Indicator normalization and structured processing
* Infrastructure enrichment (DNS, ASN, WHOIS)
* Graph-based modeling using Neo4j
* Campaign clustering via infrastructure connectivity
* Explainable campaign evidence scoring
* Attribution signal generation
* Timeline-based campaign tracking
* API-based investigation workflows

---

## System Pipeline

```
Ingestion → Enrichment → Graph → Clustering → Evidence → Campaigns → API
```

---

## Example Output

```json
{
  "campaign_id": "cmp_17",
  "indicators": 23,
  "evidence": {
    "shared_asn": true,
    "shared_nameserver": true,
    "shared_hosting": true,
    "temporal_overlap": false
  },
  "confidence_score": 0.82
}
```

---

## Architecture Summary

Aletheia follows a modular pipeline architecture:

* **Ingestion Layer** – Collects IOCs from external feeds
* **Processing Layer** – Normalizes and structures indicators
* **Enrichment Engine** – Adds infrastructure intelligence
* **Graph Engine** – Builds relationships in Neo4j
* **Correlation Engine** – Detects clusters
* **Campaign Engine** – Creates campaigns
* **Evidence Engine** – Computes explainable signals
* **API Layer** – Exposes intelligence

---

## Why Aletheia Matters

Aletheia shifts threat intelligence from:

```
isolated indicators → structured adversary campaigns
```

This enables:

* Better threat visibility
* Improved attribution reasoning
* Scalable intelligence analysis
* Analyst-friendly investigation workflows

---

## Research Positioning

Aletheia is designed as a research system focused on:

* Graph-based infrastructure correlation
* Deterministic campaign clustering
* Explainable evidence modeling
* Attribution signal generation

---

## Tech Stack

* **Backend**: Python (FastAPI)
* **Database**: PostgreSQL
* **Graph Database**: Neo4j
* **Queue System**: Redis
* **Workers**: Async processing pipeline

---

## Project Status

```
Status: Research-Complete (Core System Functional)
```

---

## Future Improvements

* Advanced clustering strategies
* Temporal campaign evolution modeling
* Infrastructure fingerprinting
* ML-assisted attribution (optional extension)

---

## License

This project is intended for research and educational purposes.

---

## Author

Developed as part of a research-focused threat intelligence system.

---
