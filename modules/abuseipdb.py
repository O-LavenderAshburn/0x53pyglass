import requests
from datetime import datetime
from config import ABUSEIPDB_KEY

def lookup(ip: str) -> dict:
    """Enrich IP using AbuseIPDB reputation"""
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    try:
        r = requests.get(url, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        data = r.json().get("data", {})
        return {
            "indicator": ip,
            "type": "ip",
            "score": data.get("abuseConfidenceScore", 0),
            "count": data.get("totalReports", 0),
            "registrar": "",
            "created": "",
            "expires": "",
            "source": "abuseipdb",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "indicator": ip,
            "type": "ip",
            "score": f"error:{e}",
            "count": "",
            "registrar": "",
            "created": "",
            "expires": "",
            "source": "abuseipdb",
            "timestamp": datetime.utcnow().isoformat()
        }
