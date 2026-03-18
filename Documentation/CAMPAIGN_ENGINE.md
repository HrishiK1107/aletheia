# Campaign Engine

### Aletheia — Adversary Campaign Correlation & Attribution

---

## 1. Overview

The Campaign Engine is the core intelligence component of Aletheia.

It is responsible for transforming clusters of related indicators into structured adversary campaigns and attaching explainable evidence to justify their grouping.

---

## 2. Purpose

The Campaign Engine solves the problem of fragmented threat intelligence by:

* Grouping related indicators into campaigns
* Generating deterministic campaign identifiers
* Attaching explainable evidence signals
* Producing confidence scores for each campaign

---

## 3. Inputs

The Campaign Engine receives:

* Clusters of indicators from the Correlation Engine
* Graph-based infrastructure relationships
* Enriched indicator metadata

---

## 4. Outputs

The Campaign Engine produces:

* Campaign objects
* Evidence signals
* Confidence scores
* Attribution hints

---

## 5. Campaign Creation Flow

```id="flow1"
Graph → Cluster Detection → Campaign Creation → Evidence Computation → Confidence Scoring → Storage
```

---

## 6. Cluster Detection

Clusters are identified using graph connectivity.

Indicators are grouped together if they share infrastructure such as:

* ASN
* IP address
* Hosting provider
* Nameserver

Each cluster represents a potential campaign.

---

## 7. Campaign Generation

Once clusters are detected, the system creates campaigns.

### 7.1 Deterministic Campaign ID

Campaign IDs are generated using deterministic hashing of cluster contents.

```id="hash1"
campaign_id = hash(sorted(indicators))
```

This ensures:

* Same cluster → same campaign
* No duplication
* Reproducibility

---

### 7.2 Campaign Structure

```json id="campjson"
{
  "campaign_id": "cmp_17",
  "indicators": [...],
  "created_at": "timestamp",
  "evidence": {},
  "confidence_score": 0.0
}
```

---

## 8. Evidence Engine (Core Innovation)

The Evidence Engine explains why a campaign exists.

Instead of just grouping indicators, Aletheia computes **evidence signals**.

---

### 8.1 Evidence Signals

The system extracts signals such as:

* Shared ASN
* Shared hosting provider
* Shared nameserver
* Shared IP
* Temporal overlap
* Domain pattern similarity
* Infrastructure reuse

---

### 8.2 Example Evidence

```json id="evidence1"
{
  "shared_asn": true,
  "shared_nameserver": true,
  "shared_hosting": true,
  "temporal_overlap": false
}
```

---

## 9. Confidence Scoring

Each campaign is assigned a confidence score.

### 9.1 Method

A weighted deterministic model is used:

```id="score1"
confidence = Σ(weight_i × signal_i)
```

---

### 9.2 Example Weights

```id="weights1"
shared_asn = 0.25
shared_nameserver = 0.20
shared_hosting = 0.15
temporal_overlap = 0.10
domain_similarity = 0.20
```

---

### 9.3 Example Output

```json id="scorejson"
{
  "confidence_score": 0.82
}
```

---

## 10. Attribution Signals

The Campaign Engine also generates attribution-related signals.

These include:

* Behavioral patterns
* Infrastructure reuse patterns
* Technique mapping

These signals assist in:

* Analyst interpretation
* Threat actor hypothesis generation

---

## 11. Campaign Lifecycle

Campaigns evolve over time.

### Events include:

* Campaign created
* Indicators added
* Indicators removed
* Campaign resolved

These events are recorded in the timeline system.

---

## 12. Storage

Campaign data is stored in PostgreSQL.

Includes:

* Campaign metadata
* Indicator associations
* Evidence signals
* Confidence scores

---

## 13. Key Strengths

* Deterministic campaign generation
* Explainable evidence modeling
* Reproducible results
* Scalable clustering approach
* Analyst-friendly outputs

---

## 14. Limitations (Current Scope)

* Evidence signals depend on enrichment quality
* No probabilistic modeling
* Attribution is signal-based, not definitive

---

## 15. Future Enhancements

* Temporal campaign evolution modeling
* Dynamic weight adjustment
* ML-assisted scoring (optional)
* Cross-campaign correlation
* Infrastructure fingerprinting

---

## 16. Research Significance

The Campaign Engine introduces a structured approach to:

```id="rs1"
Transform infrastructure connectivity into explainable adversary campaigns
```

This makes Aletheia suitable for research in:

* Threat intelligence
* Graph-based correlation
* Adversary modeling
* Cyber attribution

---

## 17. Conclusion

The Campaign Engine is the core intelligence layer of Aletheia.

By combining graph-based clustering with deterministic evidence scoring, it enables reliable, explainable, and scalable adversary campaign detection.

---
