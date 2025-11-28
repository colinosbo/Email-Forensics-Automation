import requests
import base64

url = "fecebook.com"
def scan_url(url, key):

    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": key}
        )

        if resp.status_code == 200:
            stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            count = stats.get("malicious", 0) + stats.get("suspicious", 0)


            # 2. Return Boolean
            return count > 0

    except Exception:
        pass
    return False
