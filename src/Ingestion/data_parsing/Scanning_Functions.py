import os, json, sys
import msal, requests
from msal import SerializableTokenCache
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import html
import re

load_dotenv()

TENANT_ID = os.getenv('TENANT_ID')
CLIENT_ID = os.getenv('CLIENT_ID')
RAW_SCOPES = (os.getenv("SCOPES") or "").split()
RESERVED = {"openid", "profile", "offline_access"}
SCOPES = [s for s in RAW_SCOPES if s not in RESERVED]

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
GRAPH = "https://graph.microsoft.com/v1.0"


def parse_spf_dkim(headers: str):
    spf_pattern = r"spf\s*=\s*(pass|fail|softfail|neutral|none)"
    dkim_pattern = r"dkim\s*=\s*(pass|fail|softfail|neutral|none)"
    spf_result, dkim_result = "unknown", "unknown"

    for h in headers:
        if h['name'].lower() == 'authentication-results':
            auth_value = h['value']
            spf_match = re.search(spf_pattern, auth_value, re.IGNORECASE)
            dkim_match = re.search(dkim_pattern, auth_value, re.IGNORECASE)
            if spf_match:
                spf_result = spf_match.group(1).strip()
            if dkim_match:
                dkim_result = dkim_match.group(1).strip()
    return {"spf": spf_result, "dkim": dkim_result}

def htmlToPlainText(body: str):
    if not isinstance(body, str):
        raise TypeError(f"body must be a string, {type(body)}")
    soup = BeautifulSoup(body, "html.parser")
    return soup.get_text(separator=' ', strip=True)

def extract_urls(text: str):
    if not text:
        return []
    url_pattern = r'((?:https?:\/\/|www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)?)'

    urls = re.findall(url_pattern, text)

    # Cleanup for punctuation
    clean_urls = [url.rstrip('.,;!?>)]') for url in urls]

    return clean_urls