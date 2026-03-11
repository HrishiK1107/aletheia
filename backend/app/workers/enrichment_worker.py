import logging
import time

from app.db.postgres import SessionLocal
from app.ingestion.enrichment.asn_lookup import lookup_asn
from app.ingestion.enrichment.dns_lookup import lookup_dns
from app.ingestion.enrichment.models.indicator_models import Indicator
from app.ingestion.enrichment.models.infrastructure_models import IndicatorEnrichment
from app.ingestion.enrichment.registrar_lookup import lookup_registrar
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def enrich_indicator(db: Session, indicator: Indicator):

    enrichment_data = {
        "asn": None,
        "hosting_provider": None,
        "nameservers": None,
        "registrar": None,
    }

    # IP enrichment
    if indicator.type == "ip":

        asn_data = lookup_asn(indicator.value)

        if asn_data:
            enrichment_data["asn"] = asn_data.get("asn")
            enrichment_data["hosting_provider"] = asn_data.get("hosting_provider")

    # Domain enrichment
    if indicator.type == "domain":

        dns_data = lookup_dns(indicator.value)

        if dns_data:
            nameservers = dns_data.get("nameservers")
            if nameservers:
                enrichment_data["nameservers"] = ",".join(nameservers)

            ips = dns_data.get("ips", [])

            # If we got IPs → resolve ASN
            if ips:
                asn_data = lookup_asn(ips[0])

                if asn_data:
                    enrichment_data["asn"] = asn_data.get("asn")
                    enrichment_data["hosting_provider"] = asn_data.get("hosting_provider")

        registrar_data = lookup_registrar(indicator.value)

        if registrar_data:
            enrichment_data["registrar"] = registrar_data.get("registrar")

    # Save enrichment
    enrichment = IndicatorEnrichment(
        indicator_id=indicator.id,
        asn=enrichment_data["asn"],
        registrar=enrichment_data["registrar"],
        hosting_provider=enrichment_data["hosting_provider"],
        nameservers=enrichment_data["nameservers"],
    )

    db.add(enrichment)
    db.commit()


def run_enrichment_batch():

    db = SessionLocal()

    try:

        indicators = db.query(Indicator).all()

        for indicator in indicators:

            try:
                enrich_indicator(db, indicator)

            except Exception as e:
                logger.error(f"Enrichment failed for {indicator.value}: {e}")

    finally:
        db.close()


def run_worker():

    logger.info("Enrichment worker started")

    while True:

        run_enrichment_batch()

        time.sleep(300)


if __name__ == "__main__":
    run_worker()
