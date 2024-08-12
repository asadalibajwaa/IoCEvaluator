import requests
import json
import re
import pandas as pd

# Function to determine the type of indicator
def determine_indicator_type(indicator):
    ip_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    domain_regex = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    hash_regex = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
    url_regex = r'^(http|https)://'

    if re.match(ip_regex, indicator):
        return "IPv4"
    elif re.match(domain_regex, indicator):
        return "domain"
    elif re.match(hash_regex, indicator):
        return "hash"
    elif re.match(url_regex, indicator):
        return "url"
    else:
        return None

# AlienVault verdict
def get_alienvault_verdict(indicator, indicator_type, api_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        general_info = response.json()
        pulse_count = general_info["pulse_info"]["count"]
        if pulse_count >= 2:
            return "Malicious"
        elif pulse_count == 1:
            return "Possibly Malicious"
        else:
            return "Not Malicious"
    else:
        return None

# VirusTotal verdict
def get_virustotal_verdict(indicator, indicator_type, api_key):
    endpoint_map = {
        "IPv4": "ip_addresses",
        "domain": "domains",
        "hash": "files",
        "url": "urls"
    }
    endpoint = endpoint_map.get(indicator_type)
    if not endpoint:
        return None

    url = f'https://www.virustotal.com/api/v3/{endpoint}/{indicator}'
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        reputation_data = response.json()
        last_analysis_stats = reputation_data["data"]["attributes"]["last_analysis_stats"]
        malicious_count = last_analysis_stats["malicious"]
        if malicious_count >= 1:
            return "Malicious"
        else:
            return "Not Malicious"
    else:
        return None

# MetaDefender verdict
def get_metadefender_verdict(indicator, indicator_type, api_key):
    endpoint_map = {
        "IPv4": "ip",
        "domain": "domain",
        "hash": "hash",
        "url": "url"
    }
    endpoint = endpoint_map.get(indicator_type)
    if not endpoint:
        return None

    url = f'https://api.metadefender.com/v4/{endpoint}/{indicator}'
    headers = {'apikey': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        response_data = json.loads(response.text)

        # Count the sources
        num_sources = len(response_data.get('lookup_results', {}).get('sources', []))

        # Count "trustworthy" and "malware"
        malware_count = 0
        for source in response_data.get('lookup_results', {}).get('sources', []):
            assessment = source.get('assessment', '').lower()
            if assessment == 'malware':
                malware_count += 1

        if malware_count >= 1:
            return "Malicious"
        else:
            return "Not Malicious"
    else:
        return None

# Weightage for verdicts (40% for AlienVault, 40% for VirusTotal, 20% for MetaDefender)
alienvault_weight = 0.4
virustotal_weight = 0.4
metadefender_weight = 0.2

# Read indicators from a CSV file
df = pd.read_csv("indicators.csv", header=None)

results = []

for indicator in df[0]:
    print(indicator)
    alienvault_api_key = "your_alienvault_api_key"
    virustotal_api_key = "your_virustotal_api_key"
    metadefender_api_key = "your_metadefender_api_key"

    # Determine the indicator type
    indicator_type = determine_indicator_type(indicator)
    if not indicator_type:
        print(f"Unknown indicator type for: {indicator}")
        continue

    # Get verdicts
    alienvault_verdict = get_alienvault_verdict(indicator, indicator_type, alienvault_api_key)
    virustotal_verdict = get_virustotal_verdict(indicator, indicator_type, virustotal_api_key)
    metadefender_verdict = get_metadefender_verdict(indicator, indicator_type, metadefender_api_key)

    # Weighted verdict
    weighted_verdict = (
        alienvault_weight * (1 if alienvault_verdict == "Malicious" else 0) +
        virustotal_weight * (1 if virustotal_verdict == "Malicious" else 0) +
        metadefender_weight * (1 if metadefender_verdict == "Malicious" else 0)
    )

    overall_verdict = "Malicious" if weighted_verdict >= 0.5 else "Not Malicious"

    # Store the results in a dictionary
    result = {
        "Indicator": indicator,
        "Type": indicator_type,
        "AlienVault Verdict": alienvault_verdict,
        "VirusTotal Verdict": virustotal_verdict,
        "MetaDefender Verdict": metadefender_verdict,
        "Overall Verdict": overall_verdict,
    }

    # Append the result to the results list
    results.append(result)

# Create a DataFrame from the results list
results_df = pd.DataFrame(results)

# Save the results to a new CSV file
results_df.to_csv("indicator_verdicts.csv", index=False)
