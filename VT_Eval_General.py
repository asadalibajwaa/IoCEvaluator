import requests
import gc
import json
from datetime import datetime
import pandas as pd
import re

gc.collect()

# Function to determine the type of indicator
def determine_indicator_type(indicator):
    ip_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    domain_regex = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    hash_regex = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
    url_regex = r'^(http|https)://'

    if re.match(ip_regex, indicator):
        return "ip_addresses"
    elif re.match(domain_regex, indicator):
        return "domains"
    elif re.match(hash_regex, indicator):
        return "files"
    elif re.match(url_regex, indicator):
        return "urls"
    else:
        return None

# Function to calculate completeness
def calculate_completeness(data, fields_to_check):
    empty_count = 0
    total_fields = len(fields_to_check)

    for field in fields_to_check:
        if field not in data['data']['attributes'] or not data['data']['attributes'][field]:
            empty_count += 1

    completeness_percentage = ((total_fields - empty_count) / total_fields) * 100
    return completeness_percentage

# Function to get reputation data from VirusTotal
def get_ioc_reputation(ioc, indicator_type, api_key):
    url = f'https://www.virustotal.com/api/v3/{indicator_type}/{ioc}'
    headers = {'x-apikey': api_key}

    response = requests.get(url, headers=headers)

    whois_freshness = None
    analysis_freshness = None

    try:
        reputation_data = response.json()

        if reputation_data is None:
            print(f"Failed to retrieve data for {indicator_type}: {ioc}")
            return None

        # Fields to check for completeness
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
            'Indicator': ioc,
            'Type': indicator_type,
            'Completeness Percentage': completeness_percentage,
            'Relevance Percentage': relevance_percentage,
            'Whois Freshness': whois_freshness,
            'Analysis Freshness': analysis_freshness
        }

        return result

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON for {indicator_type}: {ioc}, Error: {e}")
        return None

# Replace with your VirusTotal API key and input/output file paths
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
INPUT_FILE_PATH = "IoC.csv"
OUTPUT_FILE_PATH = "VT_output_stats.csv"

# Read indicators from the CSV file
indicators = pd.read_csv(INPUT_FILE_PATH, header=None)[0].tolist()

results_list = []

# Get stats for each indicator
for indicator in indicators:
    indicator_type = determine_indicator_type(indicator)
    if indicator_type:
        result = get_ioc_reputation(indicator, indicator_type, VIRUSTOTAL_API_KEY)
        if result is not None:
            results_list.append(result)
    else:
        print(f"Unknown indicator type for: {indicator}")

# Create a DataFrame from the results list
results_df = pd.DataFrame(results_list)
results_df.to_csv(OUTPUT_FILE_PATH, index=False)

print("Results saved to:", OUTPUT_FILE_PATH)
