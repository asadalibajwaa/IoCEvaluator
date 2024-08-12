import requests
import gc
import json
from datetime import datetime
import pandas as pd

gc.collect()

def calculate_completeness(data, fields_to_check):
    empty_count = 0
    total_fields = len(fields_to_check)

    for field in fields_to_check:
        if field not in data['data']['attributes'] or not data['data']['attributes'][field]:
            empty_count += 1

    completeness_percentage = ((total_fields - empty_count) / total_fields) * 100
    return completeness_percentage

def get_ioc_reputation(ioc, api_key):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ioc}'
    headers = {'x-apikey': api_key}

    response = requests.get(url, headers=headers)

    whois_freshness = None
    analysis_freshness = None

    try:
        reputation_data = response.json()

        if reputation_data is None:
            print(f"Failed to retrieve data for IP address: {ioc}")
            return None

        #Fields to check for completeness
        fields_to_check = [
            'network', 'tags', 'whois', 'last_analysis_date', 'as_owner',
            'last_analysis_stats', 'asn', 'whois_date', 'reputation',
            'last_analysis_results', 'country', 'last_modification_date',
            'regional_internet_registry', 'continent', 'total_votes'
        ]

        relevance_fields = [
            'id', 'type', 'created', 'modified', 'name', 'description', 'labels', 'external_references',
            'object_marking_refs', 'as_owner', 'created_by_ref', 'valid_from', 'valid_until',
            'kill_chain_phases', 'indicators', 'threat_actors', 'malware', 'attack_patterns',
            'courses_of_action', 'incident', 'infrastructure', 'sightings', 'relationships',
            'custom properties'
        ]

        # Calculate completeness
        completeness_percentage = calculate_completeness(reputation_data, fields_to_check)

        # Calculate relevance
        relevance_total_fields = len(relevance_fields)
        present_elements_relevance = sum(1 for element in relevance_fields if element in reputation_data['data']['attributes'])
        relevance_percentage = (present_elements_relevance / relevance_total_fields) * 100

        # Extract the timestamps
        whois_timestamp = reputation_data['data']['attributes'].get('whois_date', None)
        analysis_timestamp = reputation_data['data']['attributes'].get('last_analysis_date', None)

        if whois_timestamp is not None and analysis_timestamp is not None:
            # Convert the timestamps to datetime
            whois_datetime = datetime.utcfromtimestamp(whois_timestamp)
            analysis_datetime = datetime.utcfromtimestamp(analysis_timestamp)

            current_time = datetime.utcnow()
            whois_freshness = current_time - whois_datetime
            analysis_freshness = current_time - analysis_datetime

            print("Last Modification Date of Whois Record: ", whois_datetime)
            print("Last Analysis Date: ", analysis_datetime)
            print("Current Time: ", current_time)
            print("Freshness (Whois Record): ", whois_freshness)
            print("Freshness (Analysis Date): ", analysis_freshness)
        else:
            print("Timestamps not available in the response.")

        
        result = {
            'IP Address': ioc,
            'Completeness Percentage': completeness_percentage,
            'Relevance Percentage': relevance_percentage,
            'Whois Freshness': whois_freshness,
            'Analysis Freshness': analysis_freshness
        }

        return result

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON for IP address: {ioc}, Error: {e}")
        return None

# Replace with your VirusTotal API key and input/output file paths
VIRUSTOTAL_API_KEY = "YOUR_VT_API_KEY"
INPUT_FILE_PATH = "ip_add22.csv"
OUTPUT_FILE_PATH = "VT_output_stats_IP.csv"

# Read IP addresses from the CSV file
ip_addresses = pd.read_csv(INPUT_FILE_PATH, header=None)[0].tolist()

results_list = []

# Get stats for each IP address obtained from csv file
for ip_address in ip_addresses:
    result = get_ioc_reputation(ip_address, VIRUSTOTAL_API_KEY)
    if result is not None:
        results_list.append(result)


results_df = pd.DataFrame(results_list)
results_df.to_csv(OUTPUT_FILE_PATH, index=False)

print("Results saved to:", OUTPUT_FILE_PATH)
