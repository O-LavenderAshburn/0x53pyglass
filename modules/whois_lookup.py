from datetime import datetime
import whois

def lookup(domain: str) -> dict:
    """Enrich domain using WHOIS registration info with clean error handling"""
    try:
        w = whois.whois(domain)
        registrar = w.get("registrar") or "N/A"
        created = w.get("creation_date") or "N/A"
        expires = w.get("expiration_date") or "N/A"

        # Convert datetime objects to strings if needed
        if isinstance(created, list):
            created = ", ".join([str(c) for c in created])
        else:
            created = str(created)

        if isinstance(expires, list):
            expires = ", ".join([str(e) for e in expires])
        else:
            expires = str(expires)

        return {
            "indicator": domain,
            "type": "domain",
            "score": "",
            "count": "",
            "registrar": registrar,
            "created": created,
            "expires": expires,
            "source": "whois",
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        # Standardize the error field instead of dumping full WHOIS output
        return {
            "indicator": domain,
            "type": "domain",
            "score": "",
            "count": "",
            "registrar": f"error: {str(e).splitlines()[0]}",  # only first line
            "created": "",
            "expires": "",
            "source": "whois",
            "timestamp": datetime.utcnow().isoformat()
        }
