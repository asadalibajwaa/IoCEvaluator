import requests
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from datetime import datetime
import pandas as pd
import re

#Determine which IoC is taken as inout
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

# Get IoC stats based on the IoC type
def get_ioc_stats(indicator, indicator_type, api_key):
    base_url = "https://otx.alienvault.com/api/v1/indicators"
    url = f"{base_url}/{indicator_type}/{indicator}/general"
    headers = {"X-OTX-API-KEY": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        print(data)

        # Extract pulses
        pulses = data.get('pulse_info', {}).get('pulses', [])

        # Check if there are no pulses
        if not pulses:
            print(f"No pulses found for {indicator_type}: {indicator}")
            return None

        # Define fields to check
        fields_to_check = ['id', 'name', 'description', 'modified', 'created', 'tags', 'references', 'adversary',
                           'targeted_countries', 'malware_families', 'attack_ids', 'industries', 'cloned_from', 'groups']

        relevance_fields = [
            'id', 'type', 'created', 'modified', 'name', 'description', 'labels', 'external_references',
            'object_marking_refs', 'source_name', 'created_by_ref', 'valid_from', 'valid_until',
            'kill_chain_phases', 'indicators', 'threat_actors', 'malware', 'attack_patterns',
            'courses_of_action', 'incident', 'infrastructure', 'sightings'
        ]

        # Calculate completeness, relevance, and freshness for each pulse
        completeness_list = []
        freshness_list = []
        relevance_list = []

        for pulse in pulses:
            empty_count = 0
            for field in fields_to_check:
                if not pulse.get(field):
                    empty_count += 1

            total_fields = len(fields_to_check)
            completeness_percentage = (((total_fields - empty_count) / total_fields) * 100)
            completeness_list.append(completeness_percentage)

            relevance_total_fields = len(relevance_fields)
            relevance_percentage = (((total_fields - empty_count) / relevance_total_fields) * 100)
            relevance_list.append(relevance_percentage)

            modified_timestamp = pulse.get('modified')
            created_timestamp = pulse.get('created')

            if modified_timestamp and created_timestamp:
                # Convert timestamps to datetime objects
                modified_datetime = datetime.strptime(modified_timestamp, '%Y-%m-%dT%H:%M:%S.%f')
                created_datetime = datetime.strptime(created_timestamp, '%Y-%m-%dT%H:%M:%S.%f')

                # Calculate freshness (time difference) for each pulse
                current_time = datetime.utcnow()
                modified_freshness = current_time - modified_datetime
                created_freshness = current_time - created_datetime

                # Append freshness values to the list
                freshness_list.append({
                    'modified_freshness': modified_freshness,
                    'created_freshness': created_freshness
                })

        # Check if there are no pulses
        if not completeness_list:
            print(f"No pulses with relevant fields found for {indicator_type}: {indicator}")
            return None

        # Calculate overall completeness, relevance, and freshness
        total_pulses = len(pulses)
        overall_completeness = sum(completeness_list) / total_pulses if total_pulses > 0 else 0
        overall_relevance = sum(relevance_list) / total_pulses if total_pulses > 0 else 0

        # Calculate overall freshness as the average freshness for all pulses
        total_modified_freshness = sum(
            freshness['modified_freshness'].total_seconds() for freshness in freshness_list) / (
                                           total_pulses * 24 * 60 * 60) if total_pulses > 0 else 0
        total_created_freshness = sum(
            freshness['created_freshness'].total_seconds() for freshness in freshness_list) / (
                                          total_pulses * 24 * 60 * 60) if total_pulses > 0 else 0

        # Convert freshness values to timedelta objects for better readability
        overall_modified_freshness = datetime.utcfromtimestamp(total_modified_freshness).strftime('%H:%M:%S')
        overall_created_freshness = datetime.utcfromtimestamp(total_created_freshness).strftime('%H:%M:%S')

        # Return the results as a dictionary
        result = {
            'Indicator': indicator,
            'Type': indicator_type,
            'Completeness': overall_completeness,
            'Relevance': overall_relevance,
            'Modified Freshness': total_modified_freshness,
            'Created Freshness': total_created_freshness
        }

        return result

    else:
        print(f"Failed to retrieve data for {indicator_type}: {indicator}")
        return None

# Replace with your AlienVault API key and input/output file paths
ALIENVAULT_API_KEY = "your_alienvault_api_key"
INPUT_FILE_PATH = "IoC.csv"
OUTPUT_FILE_PATH = "AV_output_stats.csv"

# Read indicators from the CSV file without a header
indicators = pd.read_csv(INPUT_FILE_PATH, header=None)[0].tolist()

# Store results in a list of dictionaries
results_list = []

# Get stats for each indicator
for indicator in indicators:
    indicator_type = determine_indicator_type(indicator)
    if indicator_type:
        result = get_ioc_stats(indicator, indicator_type, ALIENVAULT_API_KEY)
        if result is not None:
            results_list.append(result)
    else:
        print(f"Unknown indicator type for: {indicator}")

# Create a DataFrame from the results list
results_df = pd.DataFrame(results_list)

# Save the results to a new CSV file
results_df.to_csv(OUTPUT_FILE_PATH, index=False)

print("Results saved to:", OUTPUT_FILE_PATH)
