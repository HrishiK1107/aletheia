import sys, time
sys.path.insert(0, '.')
from app.db.postgres import SessionLocal
from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment
from app.services.normalization_service import canonicalize_indicator_type

t0 = time.time()
db = SessionLocal()

ip_port_rows = db.query(Indicator).filter(Indicator.type == "ip:port").all()
print(f"found {len(ip_port_rows)} Indicator rows with type=ip:port", flush=True)

existing_ip_values = {v for (v,) in db.query(Indicator.value).filter(Indicator.type == "ip").all()}
print(f"existing plain-ip indicators: {len(existing_ip_values)}", flush=True)

updated_ids = []
collisions = 0
unparseable = 0

for row in ip_port_rows:
    canonical_value, canonical_type = canonicalize_indicator_type(row.value, row.type)

    if canonical_type != "ip":
        unparseable += 1
        continue

    if canonical_value in existing_ip_values:
        collisions += 1
        continue

    row.value = canonical_value
    row.type = "ip"
    updated_ids.append(row.id)
    existing_ip_values.add(canonical_value)  # avoid creating a fresh collision within this same batch

db.commit()
print(f"updated {len(updated_ids)} rows to type=ip; {collisions} collisions with an existing plain-ip indicator (left as ip:port); {unparseable} unparseable (left as ip:port)", flush=True)

# delete stale (all-null) enrichment rows for the updated indicators so run_enrichment_batch() re-enriches them
deleted = (
    db.query(IndicatorEnrichment)
    .filter(IndicatorEnrichment.indicator_id.in_(updated_ids))
    .delete(synchronize_session=False)
)
db.commit()
print(f"deleted {deleted} stale enrichment rows for updated indicators", flush=True)
db.close()

print(f"prep done in {time.time()-t0:.1f}s, running enrichment batch...", flush=True)

from app.workers.enrichment_worker import run_enrichment_batch
run_enrichment_batch()

print(f"enrichment batch done, total elapsed {time.time()-t0:.1f}s", flush=True)

# report actual coverage gained
db = SessionLocal()
enrichments = {
    e.indicator_id: e
    for e in db.query(IndicatorEnrichment).filter(IndicatorEnrichment.indicator_id.in_(updated_ids)).all()
}
n_asn = sum(1 for e in enrichments.values() if e.asn)
n_hosting = sum(1 for e in enrichments.values() if e.hosting_provider)
n_any = sum(1 for e in enrichments.values() if e.asn or e.hosting_provider)
n_no_row = len(updated_ids) - len(enrichments)

print(f"\n=== actual coverage gained, {len(updated_ids)} updated indicators ===")
print(f"  got an ASN:              {n_asn}/{len(updated_ids)} ({100*n_asn/len(updated_ids):.1f}%)")
print(f"  got a hosting_provider:  {n_hosting}/{len(updated_ids)} ({100*n_hosting/len(updated_ids):.1f}%)")
print(f"  got ASN or hosting:      {n_any}/{len(updated_ids)} ({100*n_any/len(updated_ids):.1f}%)")
print(f"  no enrichment row at all after batch: {n_no_row}")
db.close()
