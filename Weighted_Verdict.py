import requests
import json
from datetime import datetime
from OTXv2 import OTXv2, IndicatorTypes
import pandas as pd

# Function to get AlienVault verdict
def get_alienvault_verdict(ip_address, api_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    headers = {
        "X-OTX-API-KEY": api_key
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        ip_general_info = response.json()
        pulse_count = ip_general_info["pulse_info"]["count"]
        if pulse_count >= 2:
            return "Malicious"
        elif pulse_count == 1:
            return "Possibly Malicious"
        else:
            return "Not Malicious"
    else:
        return None

# Function to get VirusTotal verdict
def get_virustotal_verdict(ip_address, api_key):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
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

# Function to get MetaDefender verdict
def get_metadefender_verdict(ip_address, api_key):
    url = f'https://api.metadefender.com/v4/ip/{ip_address}'
    headers = {'apikey': api_key}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        response_data = json.loads(response.text)
        #print(response_data)

        # Count the number of sources
        num_sources = len(response_data.get('lookup_results', {}).get('sources', []))

        # Count the number marked as "trustworthy" and "malware"
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

# Read IP addresses from a CSV file (assuming it has a column named "IP")
df = pd.read_csv("ip_add_extracted.csv", header=None)

# Create a list to store results
results = []

# Loop through each IP address
for ip_address in df[0]:
    # API keys for the services
    print(ip_address)
    alienvault_api_key = "3b46a710c6ec819691528d1526764d8dd7ae82a2c96fc77fe45d6456ee12bd3c"
    virustotal_api_key = "4a35e71e00d2aa0a41b61443a1d002aaf0f8e7d1a44f3ff1c93c63233c7fe6a0"
    metadefender_api_key = "256251102612f4174a6037e3b1fcad41"

    # Get verdicts from each service
    alienvault_verdict = get_alienvault_verdict(ip_address, alienvault_api_key)
    virustotal_verdict = get_virustotal_verdict(ip_address, virustotal_api_key)
    metadefender_verdict = get_metadefender_verdict(ip_address, metadefender_api_key)

    # Calculate the overall weighted verdict
    weighted_verdict = (
        alienvault_weight * (1 if alienvault_verdict == "Malicious" else 0) +
        virustotal_weight * (1 if virustotal_verdict == "Malicious" else 0) +
        metadefender_weight * (1 if metadefender_verdict == "Malicious" else 0)
    )

    # Make a decision based on the overall weighted verdict
    overall_verdict = "Malicious" if weighted_verdict >= 0.5 else "Not Malicious"

    # Store the results in a dictionary
    result = {
        "IP": ip_address,
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
results_df.to_csv("ip_verdicts_extracted.csv", index=False)
