import json
from src.Threat_Intel.Scanning_Modules.virustotal import scan_url


def load_keys():
    with open("../../../IT-360-Group-Project-Sect-1/src/Threat_Intel/keys.json") as f:
        return json.load(f)


def VirusTotalScan(url):

    target = (url).strip()
    if not target.startswith("http"):
        target = f"http://{target}"

    keys = load_keys()

    # This prints the text automatically AND grabs the boolean
    is_malicious = scan_url(target, keys["virustotal_key"])

    # Proof it returns a boolean
    return is_malicious
