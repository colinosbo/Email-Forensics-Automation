import requests
from src.Clients.ms_graph import MicrosoftGraphClient
from src.Ingestion.data_parsing import Scanning_Functions
from src.Threat_Intel import Threat_Intel_Scan

# connect + authentication
client = MicrosoftGraphClient()
client.get_token()

# currently grabs the last email
email = client.get_latest_message()

id = email.get("id") #Retreives email ID
headers = client.get_email_headers(id) #Uses ID to grab email headers

if not email:
    print("No messages found. Try g.debug_list_folders() or g.get_latest_received_anywhere().")
else:
    plain_body = Scanning_Functions.htmlToPlainText(email["body"]["content"])
    spf_dkim_result = Scanning_Functions.parse_spf_dkim(headers)  # Setting SPF and Dkim variables
    spf = spf_dkim_result["spf"]
    dkim = spf_dkim_result["dkim"]
    #extract URLs using Regex
    urls = Scanning_Functions.extract_urls(plain_body)

    #Scam URLs in virustotal and append to the correct list
    for url in urls:
        threat_scan = Threat_Intel_Scan.VirusTotalScan(url)

    malicious_urls = []
    clean_urls = []
    for url in urls:
        # Check if the URL is malicious
        is_malicious = Threat_Intel_Scan.VirusTotalScan(url)
        if is_malicious:
            malicious_urls.append(url)
        else:
            clean_urls.append(url)

    if threat_scan:
        print("  FINAL VERDICT:  MALICIOUS  (Threats Detected)")
    elif spf != 'pass' or dkim != 'pass':
        print("  FINAL VERDICT:  SUSPICIOUS (Auth Failed)")
    else:
        print("  FINAL VERDICT:  CLEAN")

    print("-" * 60)

    # 2. METADATA
    print("  EMAIL METADATA:")
    sender = email.get("from", {}).get("emailAddress", {}).get("address")
    subject = email.get("subject")
    received = email.get("receivedDateTime")

    print(f"   • {'SENDER':<12}: {sender}")
    print(f"   • {'SUBJECT':<12}: {subject}")
    print(f"   • {'RECEIVED':<12}: {received}")
    print(f"   • {'BODY':<12}: {plain_body}")
    print(f"   • {'MSG ID':<12}: {id}")

    print("-" * 60)

    # 3. AUTHENTICATION CHECKS
    print("  AUTHENTICATION RESULTS:")
    print(f"   • SPF Status  : {spf.upper() if spf else 'UNKNOWN'}")
    print(f"   • DKIM Status : {dkim.upper() if dkim else 'UNKNOWN'}")

    print("-" * 60)

    # 4. THREAT INTEL SUMMARY
    print("  URL SCANNING SUMMARY:")
    print(f"   • Total URLs found : {len(urls)}")

    if threat_scan:
        print("\n   [!] MALICIOUS LINKS:")
        for bad_url in malicious_urls:
            print(f"       -> {bad_url}")
    if clean_urls:
        print("\n   [ok] CLEAN LINKS:")
        for url in clean_urls:
            print(f"       -> {url}")

    print("-" * 60)