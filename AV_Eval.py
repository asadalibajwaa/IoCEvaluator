import requests
import json
from OTXv2 import OTXv2
from OTXv2 import IndicatorTypes
from datetime import datetime
import pandas as pd

def get_ioc_stats(ip_address, api_key):
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general"
    headers = {"X-OTX-API-KEY": api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        print(data)

        # Extract the 'pulses' list from the JSON response
        pulses = data.get('pulse_info', {}).get('pulses', [])

        # Check if there are no pulses
        if not pulses:
            print(f"No pulses found for IP address: {ip_address}")
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
            print(f"No pulses with relevant fields found for IP address: {ip_address}")
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
            'IP Address': ip_address,
            'Completeness': overall_completeness,
            'Relevance': overall_relevance,
            'Modified Freshness': total_modified_freshness,
            'Created Freshness': total_created_freshness
        }

        return result

    else:
        print(f"Failed to retrieve data for IP address: {ip_address}")
        return None


# Replace with your AlienVault API key and input/output file paths
ALIENVAULT_API_KEY = "3b46a710c6ec819691528d1526764d8dd7ae82a2c96fc77fe45d6456ee12bd3c"
INPUT_FILE_PATH = "ip_add22.csv"
OUTPUT_FILE_PATH = "av_output_stats.csv"

# Read IP addresses from the CSV file without a header
ip_addresses = pd.read_csv(INPUT_FILE_PATH, header=None)[0].tolist()

# Store results in a list of dictionaries
results_list = []

# Get stats for each IP address
for ip_address in ip_addresses:
    result = get_ioc_stats(ip_address, ALIENVAULT_API_KEY)
    if result is not None:
        results_list.append(result)

# Create a DataFrame from the results list
results_df = pd.DataFrame(results_list)

# Save the results to a new CSV file
results_df.to_csv(OUTPUT_FILE_PATH, index=False)

print("Results saved to:", OUTPUT_FILE_PATH)
