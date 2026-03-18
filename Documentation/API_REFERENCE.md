# API Reference

### Aletheia — Intelligence Access Layer

---

## 1. Overview

The Aletheia API provides programmatic access to the threat intelligence pipeline, enabling ingestion, campaign detection, infrastructure pivoting, and intelligence retrieval.

The API is designed to support both:

* Automated processing workflows
* Analyst-driven investigation

---

## 2. Base URL

```bash
http://localhost:8000
```

---

## 3. API Structure

The API is organized into the following groups:

* Indicators
* Feeds
* Campaigns
* Pivot
* System / Health

---

## 4. Indicators

---

### 4.1 Get All Indicators

```http
GET /indicators/
```

**Description:**
Retrieve all stored indicators.

---

### 4.2 Create Indicator

```http
POST /indicators/
```

**Description:**
Create a new indicator manually.

**Request Example:**

```json
{
  "value": "example.com",
  "type": "domain"
}
```

---

### 4.3 Get Indicator by ID

```http
GET /indicators/{indicator_id}
```

**Description:**
Retrieve a specific indicator.

---

## 5. Feeds

---

### 5.1 Collect Threat Intelligence Feeds

```http
GET /feeds/collect
```

**Description:**
Triggers ingestion from external threat intelligence sources.

**Purpose:**

* Pull new IOCs
* Populate pipeline

---

## 6. Campaigns

---

### 6.1 Get All Campaigns

```http
GET /campaigns/
```

**Description:**
Retrieve all detected campaigns.

---

### 6.2 Get Campaign by ID

```http
GET /campaigns/{campaign_id}
```

**Description:**
Retrieve detailed campaign data including indicators, evidence, and confidence score.

---

### 6.3 Get Campaign Timeline

```http
GET /campaigns/{campaign_id}/timeline
```

**Description:**
Retrieve lifecycle events for a campaign.

---

### 6.4 Run Campaign Detection

```http
POST /campaigns/run
```

**Description:**
Triggers campaign detection pipeline.

**Pipeline Includes:**

* Graph traversal
* Cluster detection
* Campaign generation
* Evidence computation

---

## 7. Pivot (Graph Intelligence)

---

### 7.1 Pivot on Domain

```http
GET /pivot/domain/{domain}
```

**Description:**
Retrieve infrastructure relationships for a domain.

**Returns:**

* Related IPs
* ASN
* Hosting provider
* Connected indicators

---

### 7.2 Pivot on IP

```http
GET /pivot/ip/{ip}
```

**Description:**
Retrieve infrastructure relationships for an IP.

**Returns:**

* Related domains
* ASN
* Associated indicators

---

## 8. System / Health Endpoints

---

### 8.1 General Health Check

```http
GET /health
```

---

### 8.2 Database Status

```http
GET /db/status
```

---

### 8.3 Redis Status

```http
GET /redis/status
```

---

### 8.4 Neo4j Status

```http
GET /neo4j/status
```

---

### 8.5 System Health

```http
GET /system/health
```

**Description:**
Provides overall system diagnostics.

---

## 9. Response Structure

Standard success response:

```json
{
  "status": "success",
  "data": {},
  "error": null
}
```

Error response:

```json
{
  "status": "error",
  "data": null,
  "error": {
    "message": "Error description"
  }
}
```

---

## 10. Execution Workflow (Important)

Typical system usage flow:

```text
1. GET /feeds/collect        → ingest indicators
2. POST /campaigns/run       → detect campaigns
3. GET /campaigns/           → view campaigns
4. GET /pivot/domain/{x}     → investigate infrastructure
5. GET /campaigns/{id}       → analyze campaign
```

---

## 11. Key Capabilities

* Full pipeline triggering via API
* Real-time campaign detection
* Graph-based infrastructure pivoting
* Campaign lifecycle tracking
* System observability

---

## 12. Future Enhancements

* Authentication & API keys
* Rate limiting
* Advanced filtering
* Pagination support
* Streaming endpoints

---

## 13. Conclusion

The Aletheia API is not a simple CRUD interface but a control and investigation layer over a full threat intelligence pipeline.

It enables both automated intelligence processing and analyst-driven exploration, making it suitable for real-world and research use cases.

---
