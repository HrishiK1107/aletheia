# Aletheia Graph Model

### Infrastructure-Centric Threat Intelligence Representation

---

## 1. Overview

Aletheia uses a graph-based data model to represent relationships between threat indicators and underlying infrastructure.

This approach enables multi-hop correlation, infrastructure pivoting, and campaign detection based on connectivity rather than isolated indicators.

---

## 2. Why Graph Modeling

Traditional threat intelligence systems treat indicators as independent data points.

This limits the ability to:

* Detect infrastructure reuse
* Identify coordinated campaigns
* Perform deep correlation

A graph model solves this by:

```id="g1x2y3"
Representing entities as nodes
Connecting them through relationships
Enabling traversal across infrastructure layers
```

---

## 3. Core Entities (Nodes)

Aletheia models the following primary node types:

---

### 3.1 Indicator

Represents raw threat intelligence data.

**Types include:**

* URL
* Domain
* IP address
* File hash

---

### 3.2 Domain

Represents registered domain names.

---

### 3.3 IP Address

Represents resolved IPs associated with domains.

---

### 3.4 ASN (Autonomous System Number)

Represents network ownership and routing infrastructure.

---

### 3.5 Hosting Provider

Represents infrastructure providers hosting services.

---

### 3.6 Nameserver

Represents DNS infrastructure used by domains.

---

### 3.7 Campaign

Represents a cluster of related indicators.

---

## 4. Relationships (Edges)

The graph is built using meaningful relationships between nodes.

---

### 4.1 INDICATES

```id="r1"
Indicator → Domain
```

Links indicators to domains.

---

### 4.2 RESOLVES_TO

```id="r2"
Domain → IP
```

Represents DNS resolution.

---

### 4.3 HOSTED_BY

```id="r3"
IP → ASN
```

Links IPs to their network owner.

---

### 4.4 SERVED_BY

```id="r4"
Domain → Hosting Provider
```

Represents hosting infrastructure.

---

### 4.5 USES_NS

```id="r5"
Domain → Nameserver
```

Represents DNS configuration.

---

### 4.6 RELATED_TO

```id="r6"
Indicator ↔ Indicator
```

Optional relationship for similarity or derived linkage.

---

### 4.7 BELONGS_TO_CAMPAIGN

```id="r7"
Indicator → Campaign
```

Associates indicators with campaigns.

---

## 5. Graph Structure Example

```id="ex1"
Indicator
   ↓
Domain
   ↓
IP
   ↓
ASN
   ↓
Hosting Provider
```

Multiple indicators may share the same infrastructure nodes, forming clusters.

---

## 6. Correlation Through Connectivity

Campaigns are identified using graph connectivity.

If multiple indicators share:

* The same ASN
* The same hosting provider
* The same nameserver
* The same IP

They are grouped into a cluster.

---

## 7. Multi-Hop Intelligence

The graph enables multi-hop traversal:

```id="hop"
Indicator → Domain → IP → ASN → Other Domains → Other Indicators
```

This allows detection of indirect relationships.

---

## 8. Infrastructure Reuse Detection

Adversaries often reuse infrastructure.

Graph modeling captures this via shared nodes:

```id="reuse"
Domain A → ASN X
Domain B → ASN X
→ Correlation signal
```

---

## 9. Campaign Representation in Graph

Campaigns are represented as nodes linked to indicators:

```id="camp"
Campaign
   ↑
Indicators
   ↑
Shared Infrastructure
```

---

## 10. Graph Query Capabilities

Using Neo4j, the system can:

* Find all indicators linked to a domain
* Pivot from IP to related domains
* Identify infrastructure clusters
* Traverse campaign relationships

---

## 11. Advantages of the Graph Model

* Enables deep correlation
* Supports real-world investigation workflows
* Captures infrastructure-level relationships
* Scales with increasing data
* Allows explainable intelligence

---

## 12. Limitations (Current Scope)

* Limited enrichment reduces graph depth
* Some relationships depend on external data availability
* No temporal edges (yet)

---

## 13. Future Enhancements

* Temporal relationships (time-based edges)
* Infrastructure fingerprinting
* Weighted relationships
* Graph-based anomaly detection

---

## 14. Conclusion

The graph model is the core of Aletheia’s intelligence capability.

By representing threat infrastructure as a connected system, Aletheia enables scalable, explainable, and effective adversary campaign correlation.

---
