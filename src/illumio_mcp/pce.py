import os
import urllib3
from illumio import PolicyComputeEngine

PCE_HOST = os.getenv("PCE_HOST")
PCE_PORT = os.getenv("PCE_PORT")
PCE_ORG_ID = os.getenv("PCE_ORG_ID")
API_KEY = os.getenv("API_KEY")
API_SECRET = os.getenv("API_SECRET")
PCE_TLS_VERIFY = os.getenv("PCE_TLS_VERIFY", "true").lower() not in ("false", "0", "no")

if not PCE_TLS_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def get_pce() -> PolicyComputeEngine:
    pce = PolicyComputeEngine(PCE_HOST, port=PCE_PORT, org_id=PCE_ORG_ID)
    pce.set_credentials(API_KEY, API_SECRET)
    pce._session.verify = PCE_TLS_VERIFY
    return pce
