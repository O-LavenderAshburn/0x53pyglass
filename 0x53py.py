import csv
import time
from modules import abuseipdb, whois_lookup
from util import is_ip
from config import INPUT_FILE, OUTPUT_FILE, SLEEP_TIME, ABUSE_SCORE_THRESHOLD

# ANSI colour codes 
COLOUR_GOOD = "\033[92m"  
COLOUR_WARN = "\033[93m"   
COLOUR_ERROR = "\033[91m"  
COLOUR_RESET = "\033[0m"

# Initialize storage
rows = []
seen = set()

# Load existing enrichment (optional)
try:
    with open(OUTPUT_FILE, newline="") as f:
        reader = csv.DictReader(f)
        rows.extend(reader)
        seen = {r["indicator"] for r in rows}
except FileNotFoundError:
    pass  # first run, file doesn't exist

# Read and process indicators
with open(INPUT_FILE) as fh:
    for line in fh:
        ind = line.strip()
        if not ind or ind in seen:
            continue
        # Do the thing
        if is_ip(ind):
            result = abuseipdb.lookup(ind)
            score = result.get("score", 0)
            colour = COLOUR_WARN if isinstance(score, int) and score > ABUSE_SCORE_THRESHOLD else COLOUR_GOOD
            
            print(f"{colour}[+] Checking IP {ind} → Score: {score}{COLOUR_RESET}")
            rows.append(result)
        else:
            result = whois_lookup.lookup(ind)
            colour = COLOUR_ERROR if "error" in str(result.get("registrar","")).lower() else COLOUR_GOOD
            print(f"{colour}[+] WHOIS lookup for {ind} → Registrar: {result.get('registrar','N/A')}{COLOUR_RESET}")
            rows.append(result)

        time.sleep(SLEEP_TIME)

# Write enrichment results
with open(OUTPUT_FILE, "w", newline="") as out:
    writer = csv.DictWriter(out, fieldnames=[
        "indicator", "type", "score", "count",
        "registrar", "created", "expires", "source", "timestamp"
    ])
    writer.writeheader()
    writer.writerows(rows)

print(f"{COLOUR_GOOD}[+] Enrichment completed! Output saved to {OUTPUT_FILE}{COLOUR_RESET}")
