# Research Context

### Aletheia — Adversary Campaign Correlation & Attribution Engine

---

## 1. Introduction

Modern cybersecurity operations rely heavily on threat intelligence derived from Indicators of Compromise (IOCs), such as domains, IP addresses, URLs, and file hashes.

However, these indicators are often fragmented, isolated, and lack contextual relationships, making it difficult to:

* Identify coordinated adversary campaigns
* Understand infrastructure reuse
* Perform reliable attribution
* Generate actionable intelligence

Aletheia is designed to address this gap by transforming isolated indicators into structured, explainable adversary campaigns.

---

## 2. Problem Statement

Current threat intelligence systems face several limitations:

### 2.1 Indicator Fragmentation

IOCs are analyzed independently without linking them to broader campaigns.

### 2.2 Lack of Infrastructure Context

Relationships between domains, IPs, and hosting providers are often underutilized.

### 2.3 Limited Explainability

Many systems cluster indicators but fail to explain *why* they are related.

### 2.4 Weak Attribution Signals

Attribution is often speculative due to lack of structured evidence.

---

## 3. Research Objective

The objective of Aletheia is to:

```text id="obj1"
Transform raw threat indicators into structured adversary campaigns
using graph-based correlation and deterministic evidence modeling.
```

---

## 4. Proposed Approach

Aletheia introduces a multi-stage approach:

### Step 1 — IOC Ingestion

Collect indicators from threat intelligence sources.

### Step 2 — Enrichment

Augment indicators with infrastructure intelligence (DNS, ASN, WHOIS).

### Step 3 — Graph Modeling

Represent entities and relationships using a graph database (Neo4j).

### Step 4 — Correlation

Detect clusters of related indicators via graph connectivity.

### Step 5 — Campaign Generation

Convert clusters into structured campaigns.

### Step 6 — Evidence Modeling

Compute explainable infrastructure evidence signals.

### Step 7 — Attribution Signals

Generate behavioral and infrastructure-based attribution hints.

---

## 5. Core Innovation

The primary contribution of Aletheia is the integration of:

### 5.1 Graph-Based Correlation

Instead of analyzing indicators in isolation, Aletheia models infrastructure relationships as a graph, enabling:

* Multi-hop correlation
* Infrastructure pivoting
* Campaign-level intelligence

---

### 5.2 Deterministic Campaign Generation

Campaigns are generated using deterministic clustering, ensuring:

* Reproducibility
* Consistency
* No duplicate campaign creation

---

### 5.3 Explainable Evidence Modeling

Aletheia introduces an evidence engine that computes signals such as:

* Shared ASN
* Shared hosting provider
* Shared nameserver
* Infrastructure reuse
* Temporal overlap

These signals are aggregated into a confidence score, making campaign formation explainable.

---

### 5.4 Intelligence Pipeline Integration

The system integrates:

* Ingestion
* Enrichment
* Graph modeling
* Correlation
* Attribution

into a unified pipeline.

---

## 6. System Contributions

Aletheia contributes the following to threat intelligence research:

```text id="contrib1"
- Graph-based infrastructure correlation framework
- Deterministic campaign clustering model
- Explainable evidence-based scoring system
- Integrated campaign lifecycle tracking
- API-driven intelligence access layer
```

---

## 7. Comparison with Existing Approaches

Traditional systems:

```text id="cmp1"
IOC → isolated analysis → limited correlation
```

Aletheia:

```text id="cmp2"
IOC → graph → correlation → evidence → campaign → attribution
```

This shift enables structured and scalable intelligence.

---

## 8. Use Cases

Aletheia can be applied to:

* Threat intelligence analysis
* SOC investigations
* Incident response
* Campaign tracking
* Infrastructure analysis

---

## 9. Limitations

Current system limitations include:

* Dependence on enrichment data quality
* Deterministic scoring (no probabilistic modeling)
* Attribution is indicative, not definitive
* Limited temporal modeling

---

## 10. Future Work

Potential research extensions:

* Temporal graph modeling
* Infrastructure fingerprinting
* Cross-campaign correlation
* Machine learning-assisted clustering
* Real-time intelligence streaming

---

## 11. Research Significance

Aletheia demonstrates that:

```text id="sig1"
Graph-based infrastructure modeling combined with deterministic evidence scoring
can produce explainable and scalable adversary campaign intelligence.
```

This contributes to the advancement of:

* Threat intelligence systems
* Cyber attribution methodologies
* Graph-based security analytics

---

## 12. Conclusion

Aletheia provides a structured and explainable approach to adversary campaign correlation.

By combining graph intelligence with deterministic evidence modeling, the system transforms fragmented indicators into meaningful intelligence, making it suitable for both academic research and real-world applications.

---
