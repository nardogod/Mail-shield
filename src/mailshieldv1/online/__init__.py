"""Optional online enrichment (DNS). Disabled unless explicitly requested."""

from mailshieldv1.online.lookups import enrich_online

__all__ = ["enrich_online"]
