# Aletheia Architecture

### Adversary Campaign Correlation & Attribution Engine

---

## 1. System Overview

Aletheia is a modular threat intelligence system designed to transform fragmented Indicators of Compromise (IOCs) into structured adversary campaigns using graph-based correlation and deterministic evidence modeling.

The system follows a pipeline architecture where data flows through distinct processing layers, each responsible for a specific transformation step.

---

## 2. Architectural Philosophy

Aletheia is built on the following design principles:

### 2.1 Modularity

Each component operates independently, enabling scalability and maintainability.

### 2.2 Determinism

Campaign detection and scoring are based on deterministic rules rather than black-box models.

### 2.3 Explainability

Every campaign is supported by evidence signals that justify its formation and confidence.

### 2.4 Graph-Centric Intelligence

Infrastructure relationships are modeled as a graph to enable multi-hop correlation.

### 2.5 Pipeline Separation

Clear separation between ingestion, enrichment, correlation, and attribution ensures clean data flow.

---

## 3. High-Level Architecture

```id="k6w1v2"
Ingestion Layer
      ↓
Processing / Normalization
      ↓
Enrichment Engine
      ↓
Graph Engine (Neo4j)
      ↓
Correlation Engine
      ↓
Campaign Engine
      ↓
Evidence Engine
      ↓
Attribution Layer
      ↓
API Layer
```

---

## 4. Component Breakdown

### 4.1 Ingestion Layer

Responsible for collecting raw IOCs from external threat intelligence sources.

**Responsibilities:**

* Fetch indicators (URLs, domains, IPs, hashes)
* Validate and filter inputs
* Push data into processing pipeline

---

### 4.2 Processing / Normalization Layer

Standardizes incoming indicators into structured formats.

**Responsibilities:**

* Normalize indicator types
* Remove duplicates
* Prepare data for enrichment

---

### 4.3 Enrichment Engine

Enhances indicators with infrastructure intelligence.

**Enrichment Types:**

* DNS resolution
* ASN lookup
* WHOIS data
* Hosting provider identification

**Purpose:**
To convert raw indicators into infrastructure-aware entities.

---

### 4.4 Graph Engine (Neo4j)

Builds and maintains relationships between entities.

**Core Idea:**
All indicators and infrastructure elements are represented as nodes and relationships.

**Capabilities:**

* Multi-hop relationship traversal
* Infrastructure pivoting
* Cluster formation via connectivity

---

### 4.5 Correlation Engine

Identifies related indicators based on graph connectivity.

**Method:**

* Detect connected components
* Group indicators sharing infrastructure

**Output:**
Clusters of related indicators

---

### 4.6 Campaign Engine

Transforms clusters into structured campaigns.

**Responsibilities:**

* Assign campaign IDs
* Aggregate indicators
* Maintain campaign lifecycle
* Store campaign metadata

---

### 4.7 Evidence Engine

Computes explainable evidence signals for each campaign.

**Signals Include:**

* Shared ASN
* Shared hosting provider
* Shared nameserver
* Temporal overlap
* Infrastructure reuse

**Output:**

* Evidence object
* Confidence score

---

### 4.8 Attribution Layer

Maps campaigns to potential adversary behaviors.

**Capabilities:**

* Technique mapping (e.g., ATT&CK alignment)
* Pattern recognition
* Attribution signal generation

---

### 4.9 API Layer

Exposes the system for external interaction.

**Functions:**

* Query campaigns
* Retrieve indicators
* Perform infrastructure pivots
* Access timeline data

---

## 5. Data Storage Architecture

### PostgreSQL

Used for:

* Indicator storage
* Campaign metadata
* Enrichment results
* Timeline events

---

### Neo4j

Used for:

* Graph relationships
* Infrastructure modeling
* Correlation queries

---

### Redis

Used for:

* Task queue
* Asynchronous processing
* Worker communication

---

## 6. Execution Flow Summary

```id="2r6n7f"
External Feeds
      ↓
Ingestion
      ↓
Normalization
      ↓
Enrichment
      ↓
Graph Construction
      ↓
Cluster Detection
      ↓
Campaign Creation
      ↓
Evidence Scoring
      ↓
API Exposure
```

---

## 7. Key Strengths of the Architecture

* Scalable pipeline design
* Clear separation of concerns
* Strong graph-based correlation model
* Deterministic and explainable outputs
* Suitable for real-world threat intelligence workflows

---

## 8. System Limitations (Current Scope)

* Limited enrichment depth (depends on data sources)
* Deterministic scoring (no probabilistic modeling yet)
* Attribution is signal-based, not fully automated

---

## 9. Future Architectural Extensions

* Temporal graph modeling
* Infrastructure fingerprinting engine
* Machine learning-assisted clustering
* Real-time streaming ingestion
* Distributed graph processing

---

## 10. Conclusion

Aletheia provides a structured and scalable architecture for transforming raw threat indicators into meaningful intelligence.

By combining graph modeling with deterministic evidence scoring, the system enables explainable adversary campaign correlation and lays the foundation for advanced threat intelligence research.

---
