import requests
import gc
import json
from datetime import datetime
import pandas as pd
import re
import time
import base64

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



FIELDS_BY_TYPE = {
    "ip_addresses": [
        'network', 'tags', 'whois', 'as_owner', 'asn', 'whois_date', 'country', 
        'last_analysis_date', 'last_analysis_stats', 'last_analysis_results',
        'regional_internet_registry', 'reputation', 'total_votes', 
        'last_modification_date', 'continent'
    ],
    "domains": [
        'network', 'tags', 'whois', 'whois_date', 'as_owner', 'country', 
        'last_analysis_date', 'last_analysis_stats', 'last_analysis_results', 
        'last_modification_date', 'reputation', 'total_votes', 
        'registrar', 'creation_date', 'expiration_date', 
        'regional_internet_registry'
    ],
    "files": [
        'tags', 'type_description', 'last_analysis_date', 'last_analysis_stats',
        'last_analysis_results', 'reputation', 'total_votes', 'magic', 
        'names', 'size', 'md5', 'sha1', 'sha256', 'first_submission_date',
        'last_modification_date'
    ],
    "urls": [
        'tags', 'last_analysis_date', 'last_analysis_stats', 
        'last_analysis_results', 'reputation', 'total_votes', 
        'last_modification_date', 'title', 'category', 'url', 
        'referrer_samples'
    ]
}


# Function to base64 encode a URL
def encode_url(url):
    # Step 1: Strip the scheme (http:// or https://)
    stripped_url = url.replace('http://', '').replace('https://', '')
    
    # Step 2: Base64 encode the stripped URL
    encoded_url = base64.urlsafe_b64encode(stripped_url.encode()).decode().strip('=')
    
    return encoded_url

# Function to calculate completeness
def calculate_completeness(data, indicator_type):
    fields_to_check = FIELDS_BY_TYPE.get(indicator_type, [])
    empty_count = 0
    total_fields = len(fields_to_check)

    for field in fields_to_check:
        if field not in data.get('data', {}).get('attributes', {}) or not data['data']['attributes'][field]:
            empty_count += 1

    completeness_percentage = ((total_fields - empty_count) / total_fields) * 100
    return completeness_percentage

# Function to safely parse timestamps
def parse_timestamp(timestamp):
    try:
        return datetime.utcfromtimestamp(timestamp)
    except Exception as e:
        print(f"Error parsing timestamp: {e}")
        return None

# Function to get reputation data from VirusTotal
def get_ioc_reputation(ioc, indicator_type, api_key):
    if indicator_type == 'urls':
        ioc = encode_url(ioc)  # Encode URL before sending to the API

    url = f'https://www.virustotal.com/api/v3/{indicator_type}/{ioc}'
    print(url)
    headers = {'x-apikey': api_key}

    try:
        response = requests.get(url, headers=headers)

        # Handle rate-limiting or other request failures
        if response.status_code == 403:  # API limit reached
            print(f"API limit reached for {indicator_type}: {ioc}")
            return {
                'Indicator': ioc,
                'Type': indicator_type,
                'Completeness Percentage': 'N/A',
                'Relevance Percentage': 'N/A',
                'Whois Freshness': 'N/A',
                'Analysis Freshness': 'N/A',
                'Last Modification Freshness': 'N/A'
            }

        reputation_data = response.json()
        print("Reputation Data:", reputation_data)

        # Check if 'data' exists in the response
        if 'data' not in reputation_data:
            print(f"Missing 'data' field in response for {indicator_type}: {ioc}")
            return {
                'Indicator': ioc,
                'Type': indicator_type,
                'Completeness Percentage': 'N/A',
                'Relevance Percentage': 'N/A',
                'Whois Freshness': 'N/A',
                'Analysis Freshness': 'N/A',
                'Last Modification Freshness': 'N/A'
            }

        # Fields to check for completeness
        #fields_to_check = [
        #    'network', 'tags', 'whois', 'last_analysis_date', 'as_owner',
        #    'last_analysis_stats', 'asn', 'whois_date', 'reputation',
        #    'last_analysis_results', 'country', 'last_modification_date',
        #    'regional_internet_registry', 'continent', 'total_votes'
        #]

        relevance_fields = [
            'id', 'type', 'created', 'modified', 'name', 'description', 'labels', 'external_references',
            'object_marking_refs', 'as_owner', 'created_by_ref', 'valid_from', 'valid_until',
            'kill_chain_phases', 'indicators', 'threat_actors', 'malware', 'attack_patterns',
            'courses_of_action', 'incident', 'infrastructure', 'sightings'
        ]

        
        

        # Calculate completeness based on URL fields
        completeness_percentage = calculate_completeness(reputation_data, indicator_type)

        # Calculate relevance
        relevance_total_fields = len(relevance_fields)
        present_elements_relevance = sum(1 for element in relevance_fields if element in reputation_data['data']['attributes'])
        relevance_percentage = (present_elements_relevance / relevance_total_fields) * 100

        # Extract the timestamps for Whois and last analysis
        whois_timestamp = reputation_data['data']['attributes'].get('whois_date', None)
        analysis_timestamp = reputation_data['data']['attributes'].get('last_analysis_date', None)
        last_modification_timestamp = reputation_data['data']['attributes'].get('last_modification_date', None)

        # Initialize freshness values
        whois_freshness = 'N/A'
        analysis_freshness = 'N/A'
        last_modification_freshness = 'N/A'
        analysis_datetime = None
        last_modification_datetime = None
        # Calculate freshness for timestamps if they are available
        if whois_timestamp is not None:
            whois_datetime = parse_timestamp(whois_timestamp)
            whois_freshness = datetime.utcnow() - whois_datetime if whois_datetime else 'N/A'

        if analysis_timestamp is not None:
            analysis_datetime = parse_timestamp(analysis_timestamp)
            analysis_freshness = datetime.utcnow() - analysis_datetime if analysis_datetime else 'N/A'

        if last_modification_timestamp is not None:
            last_modification_datetime = parse_timestamp(last_modification_timestamp)
            last_modification_freshness = datetime.utcnow() - last_modification_datetime if last_modification_datetime else 'N/A'

        # Print or log freshness information
        print("Last Modification Date: ", last_modification_datetime)
        print("Last Analysis Date: ", analysis_datetime)
        print("Current Time: ", datetime.utcnow())
        print("Freshness (Whois Record): ", whois_freshness)
        print("Freshness (Analysis Date): ", analysis_freshness)
        print("Freshness (Last Modification): ", last_modification_freshness)

        # Generate the final result
        result = {
            'Indicator': ioc,
            'Type': indicator_type,
            'Completeness Percentage': completeness_percentage,
            'Relevance Percentage': relevance_percentage,
            'Whois Freshness': whois_freshness,
            'Analysis Freshness': analysis_freshness,
            'Last Modification Freshness': last_modification_freshness
        }

        return result

    except json.JSONDecodeError as e:
        print(f"Error decoding JSON for {indicator_type}: {ioc}, Error: {e}")
        return {
            'Indicator': ioc,
            'Type': indicator_type,
            'Completeness Percentage': 'N/A',
            'Relevance Percentage': 'N/A',
            'Whois Freshness': 'N/A',
            'Analysis Freshness': 'N/A',
            'Last Modification Freshness': 'N/A'
        }

# Replace with your VirusTotal API key and input/output file paths
VIRUSTOTAL_API_KEY = "your_virustotal_api_key" # replace this with your virustotal API key
INPUT_FILE_PATH = "Your input file.csv" # replace this with your input file that has IoCs
OUTPUT_FILE_PATH = "Your output file.csv" # replace this with your desired output file


# Read indicators from the CSV file
indicators = pd.read_csv(INPUT_FILE_PATH, header=None)[0].tolist()

results_list = []

# Get stats for each indicator
for indicator in indicators:
    indicator_type = determine_indicator_type(indicator)
    print(indicator_type)
    if indicator_type:
        result = get_ioc_reputation(indicator, indicator_type, VIRUSTOTAL_API_KEY)
        if result is not None:
            results_list.append(result)
    else:
        print(f"Unknown indicator type for: {indicator}")

    # Sleep to avoid hitting rate limits too quickly (can adjust based on actual limits)
    time.sleep(1)

# Create a DataFrame from the results list
results_df = pd.DataFrame(results_list)
results_df.to_csv(OUTPUT_FILE_PATH, index=False)

print("Results saved to:", OUTPUT_FILE_PATH)
