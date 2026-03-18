# Data Flow

### Aletheia — End-to-End Data Movement

---

## 1. Overview

This document describes how data flows through Aletheia from ingestion to final intelligence output.

The system is designed as an asynchronous, multi-stage pipeline where data is progressively transformed into structured adversary intelligence.

---

## 2. High-Level Data Flow

```id="df1"
External Feeds → Ingestion → Redis Queue → Workers → PostgreSQL → Neo4j → Correlation Engine → Campaign Engine → API
```

---

## 3. Data Flow Stages

---

### 3.1 External Data Sources

**Inputs:**

* Threat intelligence feeds
* Indicator datasets

**Data Types:**

* URLs
* Domains
* IP addresses
* File hashes

---

### 3.2 Ingestion Layer

**Process:**

* Fetch raw indicators
* Validate format
* Push data to Redis queue

**Output:**
Raw IOC messages

---

### 3.3 Redis Queue

**Purpose:**
Acts as a buffer between ingestion and processing.

**Benefits:**

* Decouples ingestion from processing
* Enables asynchronous execution
* Improves scalability

---

### 3.4 Worker Layer

Workers process queued data.

#### Responsibilities:

---

#### a) Normalization

* Standardize indicator format
* Remove duplicates
* Assign internal IDs

---

#### b) Enrichment

* Perform DNS lookups
* Retrieve ASN information
* Fetch WHOIS data
* Identify hosting providers

---

**Output:**
Enriched indicator objects

---

### 3.5 PostgreSQL Storage

Stores structured data.

**Stored Data:**

* Indicators
* Enrichment results
* Campaign metadata
* Timeline events

---

### 3.6 Graph Construction (Neo4j)

**Process:**

* Create nodes (indicator, domain, IP, ASN, etc.)
* Create relationships between nodes

**Purpose:**
Represent infrastructure connections

---

### 3.7 Correlation Engine

**Function:**

* Traverse graph
* Identify connected components
* Generate clusters

**Output:**
Indicator clusters

---

### 3.8 Campaign Engine

**Function:**

* Convert clusters into campaigns
* Assign campaign IDs
* Aggregate indicators

---

### 3.9 Evidence Engine

**Function:**

* Compute evidence signals
* Generate confidence scores

---

### 3.10 Attribution Layer

**Function:**

* Map behaviors
* Generate attribution signals

---

### 3.11 API Layer

**Purpose:**
Expose intelligence data to users and systems.

**Capabilities:**

* Campaign queries
* Indicator lookup
* Infrastructure pivoting
* Timeline access

---

## 4. Detailed Data Flow Sequence

```id="df2"
1. External feed provides IOC
2. Ingestion fetches and validates data
3. IOC pushed to Redis queue
4. Worker consumes IOC
5. Indicator normalized
6. Enrichment performed
7. Data stored in PostgreSQL
8. Graph updated in Neo4j
9. Correlation engine detects clusters
10. Campaign engine generates campaigns
11. Evidence engine computes signals
12. Attribution layer adds context
13. API exposes results
```

---

## 5. Data Transformation Summary

```id="df3"
Raw IOC
   ↓
Structured Indicator
   ↓
Enriched Indicator
   ↓
Graph Node
   ↓
Cluster Member
   ↓
Campaign Entity
   ↓
Attributed Intelligence
```

---

## 6. Key Characteristics

### 6.1 Asynchronous Processing

* Redis-based queue system
* Workers process data independently

---

### 6.2 Incremental Updates

* New data continuously updates the graph
* Campaigns evolve over time

---

### 6.3 Fault Tolerance (Current Scope)

* Failed enrichment does not stop pipeline
* Partial data is still processed
* Invalid indicators are discarded

---

### 6.4 Deterministic Flow

* Same input produces same campaign output
* Ensures reproducibility

---

## 7. Strengths

* Scalable pipeline architecture
* Clear separation of responsibilities
* Supports real-world intelligence workflows
* Enables explainable campaign generation

---

## 8. Limitations

* Dependent on external data quality
* Enrichment failures reduce graph depth
* No real-time streaming (yet)

---

## 9. Future Enhancements

* Real-time streaming ingestion
* Distributed worker architecture
* Improved enrichment reliability
* Event-driven pipeline triggers

---

## 10. Conclusion

The data flow architecture of Aletheia ensures a clean, scalable, and deterministic transformation of raw threat data into actionable intelligence.

By structuring data movement across well-defined stages, the system enables reliable campaign detection and explainable threat analysis.

---
