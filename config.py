from dotenv import load_dotenv
import os

# Load .env file
load_dotenv()

# API Keys
ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

# File paths
INPUT_FILE = os.getenv("INPUT_FILE", "data/indicators.txt")
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "data/enrichment.csv")

# General settings
SLEEP_TIME = float(os.getenv("SLEEP_TIME", 1))  # seconds delay between requests
ABUSE_SCORE_THRESHOLD = int(os.getenv("ABUSE_SCORE_THRESHOLD", 50))  # optional threshold
