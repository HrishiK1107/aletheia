# Aletheia Pipeline

### End-to-End Data Processing Flow

---

## 1. Overview

Aletheia follows a structured, multi-stage pipeline that transforms raw Indicators of Compromise (IOCs) into enriched, correlated, and explainable adversary campaigns.

Each stage in the pipeline performs a specific transformation, ensuring clarity, modularity, and scalability.

---

## 2. Pipeline Summary

```id="f4z7x1"
Ingestion → Normalization → Enrichment → Graph Construction → Correlation → Campaign Generation → Evidence Scoring → Attribution → API Exposure
```

---

## 3. Step-by-Step Pipeline

---

### Step 1: IOC Ingestion

**Input Sources:**

* External threat intelligence feeds
* Indicator datasets

**Data Types:**

* URLs
* Domains
* IP addresses
* File hashes

**Process:**

* Fetch raw indicators
* Perform basic validation
* Push to processing queue (Redis)

**Output:**
Raw IOC stream

---

### Step 2: Indicator Normalization

**Purpose:**
Convert raw indicators into a structured and consistent format.

**Operations:**

* Standardize indicator types
* Remove duplicates
* Validate formats
* Assign internal identifiers

**Output:**
Normalized indicators

---

### Step 3: Enrichment

**Purpose:**
Enhance indicators with infrastructure intelligence.

**Enrichment Types:**

* DNS resolution
* ASN lookup
* WHOIS data
* Hosting provider identification

**Example Transformation:**

```id="kl8t1z"
domain → IP → ASN → hosting provider
```

**Output:**
Enriched indicators with infrastructure metadata

---

### Step 4: Graph Construction

**Purpose:**
Model relationships between indicators and infrastructure.

**Process:**

* Create nodes (indicator, domain, IP, ASN, etc.)
* Create relationships (RESOLVES_TO, HOSTED_BY, etc.)
* Store in Neo4j

**Graph Representation:**

```id="w8q1m2"
Indicator → Domain → IP → ASN → Hosting
```

**Output:**
Connected infrastructure graph

---

### Step 5: Correlation (Cluster Detection)

**Purpose:**
Identify groups of related indicators based on shared infrastructure.

**Method:**

* Traverse graph
* Detect connected components
* Group indicators into clusters

**Output:**
Clusters of related indicators

---

### Step 6: Campaign Generation

**Purpose:**
Convert clusters into structured campaigns.

**Process:**

* Assign campaign ID (deterministic hashing)
* Aggregate indicators
* Store campaign metadata

**Output:**
Campaign objects

---

### Step 7: Evidence Scoring

**Purpose:**
Explain why a campaign exists and quantify confidence.

**Evidence Signals:**

* Shared ASN
* Shared hosting provider
* Shared nameserver
* Temporal overlap
* Infrastructure reuse

**Scoring:**

* Weighted aggregation of signals
* Deterministic confidence score

**Output:**
Campaign with evidence and confidence

---

### Step 8: Attribution

**Purpose:**
Generate adversary behavior signals.

**Capabilities:**

* Technique mapping
* Pattern recognition
* Behavioral indicators

**Output:**
Attribution-enriched campaigns

---

### Step 9: API Exposure

**Purpose:**
Provide access to intelligence data.

**Endpoints:**

* Campaign queries
* Indicator retrieval
* Infrastructure pivoting
* Timeline access

**Output:**
Usable intelligence interface

---

## 4. Data Flow Visualization

```id="i3n2k7"
External Feeds
      ↓
Ingestion (Collectors)
      ↓
Redis Queue
      ↓
Workers (Processing + Enrichment)
      ↓
PostgreSQL (Storage)
      ↓
Neo4j (Graph)
      ↓
Correlation Engine
      ↓
Campaign Engine
      ↓
Evidence Engine
      ↓
API Layer
```

---

## 5. Key Pipeline Characteristics

### 5.1 Asynchronous Processing

Workers process data independently using Redis queues.

### 5.2 Incremental Updates

New indicators continuously update the graph and campaigns.

### 5.3 Deterministic Outputs

Campaigns and scores are reproducible.

### 5.4 Graph-Based Correlation

Multi-hop relationships enable deeper intelligence.

---

## 6. Failure Handling (Current Scope)

* Invalid indicators are discarded
* Enrichment failures do not stop pipeline
* Partial data still contributes to graph

---

## 7. Pipeline Strengths

* Clear separation of stages
* Scalable architecture
* Supports real-world intelligence workflows
* Enables explainable campaign generation

---

## 8. Future Enhancements

* Real-time streaming ingestion
* Batch optimization
* Distributed processing
* Advanced temporal correlation

---

## 9. Conclusion

The Aletheia pipeline provides a structured approach to transforming raw threat data into meaningful intelligence.

By combining enrichment, graph modeling, and deterministic evidence scoring, the pipeline enables reliable and explainable adversary campaign detection.

---
