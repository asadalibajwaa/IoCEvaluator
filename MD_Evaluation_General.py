##This one works well

import json
from datetime import datetime, timezone
import requests
import csv
import re
from urllib.parse import quote

# Function to determine the type of indicator
def determine_indicator_type(indicator):
    ip_regex = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    domain_regex = r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    hash_regex = r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
    url_regex = r'^(http|https)://'

    if re.match(ip_regex, indicator):
        return "ip"
    elif re.match(domain_regex, indicator):
        return "domain"
    elif re.match(hash_regex, indicator):
        return "hash"
    elif re.match(url_regex, indicator):
        return "url"
    else:
        return None

# Function to analyze the MetaDefender response
def analyze_metadefender_response(response_data, indicator_type):
    
    if indicator_type == "ip":
        return analyze_ip_response(response_data)
    elif indicator_type == "hash":
        return analyze_hash_response(response_data)
    elif indicator_type == "domain":
        return analyze_domain_response(response_data)
    elif indicator_type == "url":
        return analyze_url_response(response_data)
    




    
    
        
def analyze_ip_response(response_data):

    # Calculate freshness (time since last update) for sources
    update_times_sources = [source.get('update_time') for source in response_data.get('lookup_results', {}).get('sources', [])]
    current_time = datetime.now(timezone.utc)

    # Calculate freshness in hours, ensuring valid times are converted
    freshness_sources = []
    for time in update_times_sources:
        if time:  # Check if time is not None or empty
            freshness = (current_time - datetime.fromisoformat(time.replace('Z', '+00:00'))).total_seconds() / 3600
            freshness_sources.append(freshness)
            #print("Freshness sources:", freshness_sources)

    valid_freshness_sources = [value for value in freshness_sources if value >= 0]
    average_freshness_sources = sum(valid_freshness_sources) / len(valid_freshness_sources) if valid_freshness_sources else 0

    # Define fields for completeness of sources
    completeness_fields_sources = ['provider', 'assessment', 'detect_time', 'update_time', 'status']

    # Calculate completeness for each source
    completeness_scores_sources = []
    for source in response_data.get('lookup_results', {}).get('sources', []):
        completeness_count = sum(1 for field in completeness_fields_sources if source.get(field))
        completeness_scores_sources.append(completeness_count / len(completeness_fields_sources) * 100)

    # Calculate average completeness percentage for sources
    average_completeness_sources = sum(completeness_scores_sources) / len(completeness_scores_sources) if completeness_scores_sources else 0

    # Define fields for completeness of geo_info
    completeness_fields_geo = ['country', 'city', 'location', 'subdivisions']

    # Calculate completeness for geo_info
    completeness_scores_geo = []
    geo_info = response_data.get('geo_info', {})
    for field in completeness_fields_geo:
        completeness_count = 1 if geo_info.get(field) else 0
        completeness_scores_geo.append(completeness_count)

    # Calculate average completeness percentage for geo_info
    average_completeness_geo = sum(completeness_scores_geo) / len(completeness_fields_geo) * 100

    # Calculate average completeness percentage including both sources and geo_info
    all_completeness_scores = completeness_scores_sources + completeness_scores_geo
    average_completeness_all = sum(all_completeness_scores) / len(all_completeness_scores) if all_completeness_scores else 0

    # Calculate relevance
    relevance_fields = [
        'id', 'type', 'created', 'modified', 'name', 'description', 'labels', 'external_references',
        'object_marking_refs', 'source_name', 'created_by_ref', 'valid_from', 'valid_until',
        'kill_chain_phases', 'indicators', 'threat_actors', 'malware', 'attack_patterns',
        'courses_of_action', 'incident', 'infrastructure', 'sightings'
    ]

    relevance_scores = []
    for field in relevance_fields:
        relevance_count = 1 if response_data.get(field) else 0
        relevance_scores.append(relevance_count)

    # Calculate average relevance percentage
    average_relevance = sum(relevance_scores) / len(relevance_fields) * 100

    return {
        'freshness_sources': average_freshness_sources,
        #'completeness_percentage_sources': average_completeness_sources,
        #'completeness_percentage_geo': average_completeness_geo,
        'completeness_percentage': average_completeness_all,
        'relevance_percentage': average_relevance
    }

def analyze_hash_response(response_data):
    hash_completeness_fields = [
        'scan_results', 'file_info', 'process_info', 'malware_type', 
        'malware_family', 'threat_name', 'last_start_time', 'sanitized', 
        'votes', 'scan_result_history_length', 'data_id', 'file_id'
    ]

    # Calculate completeness
    completeness_scores = [
        1 if response_data.get(field) else 0
        for field in hash_completeness_fields
    ]
    average_completeness = sum(completeness_scores) / len(hash_completeness_fields) * 100

    # Calculate freshness based on scan results
    scan_details = response_data.get('scan_results', {}).get('scan_details', {})
    def_times = [scanner.get('def_time') for scanner in scan_details.values()]
    current_time = datetime.now(timezone.utc)
    freshness_values = [
        (current_time - datetime.fromisoformat(def_time.replace('Z', '+00:00'))).total_seconds() / 3600
        for def_time in def_times if def_time
    ]
    valid_freshness_sources = [value for value in freshness_values if value >= 0]
    average_freshness = sum(valid_freshness_sources) / len(valid_freshness_sources) if valid_freshness_sources else 0

    # Calculate relevance
    relevance_fields = [
        'id', 'type', 'created', 'modified', 'name', 'description', 'labels', 'external_references',
        'object_marking_refs', 'source_name', 'created_by_ref', 'valid_from', 'valid_until',
        'kill_chain_phases', 'indicators', 'threat_actors', 'malware', 'attack_patterns',
        'courses_of_action', 'incident', 'infrastructure', 'sightings'
    ]
    relevance_scores = [1 if response_data.get(field) else 0 for field in relevance_fields]
    average_relevance = sum(relevance_scores) / len(relevance_fields) * 100

    return {
        'freshness_sources': average_freshness,
        'completeness_percentage': average_completeness,
        'relevance_percentage': average_relevance,
    }



def analyze_domain_response(response_data):
    # Extract lookup results and sources
    lookup_results = response_data.get('lookup_results', {})
    sources = lookup_results.get('sources', [])

    # Calculate freshness
    current_time = datetime.now(timezone.utc)
    freshness_sources = []
    for source in sources:
        update_time = source.get('update_time')
        if update_time:
            freshness = (current_time - datetime.fromisoformat(update_time.replace('Z', '+00:00'))).total_seconds() / 3600
            freshness_sources.append(freshness)

    valid_freshness_sources = [value for value in freshness_sources if value >= 0]
    average_freshness_sources = sum(valid_freshness_sources) / len(valid_freshness_sources) if valid_freshness_sources else 0

    # Calculate completeness based on more fields
    completeness_fields = [
        'provider', 'assessment', 'category', 'detect_time', 'update_time', 
        'status', 'start_time', 'detected_by', 'sources'
    ]
    
    completeness_scores = []
    for source in sources:
        completeness_count = sum(1 for field in completeness_fields if source.get(field))
        completeness_scores.append(completeness_count / len(completeness_fields) * 100)

    average_completeness_sources = sum(completeness_scores) / len(completeness_scores) if completeness_scores else 0

    # Detection relevance
    detected_by = lookup_results.get('detected_by', 0)
    total_sources = len(sources)
    detection_relevance = (detected_by / total_sources) * 100 if total_sources else 0
    print("Detection Relevance:", detection_relevance)

    # Relevance (based on fields present in lookup_results)
    relevance_fields = [
        'start_time', 'detected_by', 'sources', 'provider', 'category', 'status'
    ]
    relevance_scores = [1 if response_data.get(field) else 0 for field in relevance_fields]
    average_relevance = sum(relevance_scores) / len(relevance_fields) * 100

    return {
        'freshness_sources': average_freshness_sources,
        'completeness_percentage': average_completeness_sources,
        #'detection_relevance': detection_relevance,
        'relevance_percentage': average_relevance,
    }


def analyze_url_response(response_data):
    # Extract `detected_by` field (specific to URLs)
    detected_by = response_data.get('lookup_results', {}).get('detected_by', 0)
    print("Detected by:", detected_by)

    # Calculate freshness for sources
    update_times_sources = [
        source.get('update_time') for source in response_data.get('lookup_results', {}).get('sources', [])
    ]
    current_time = datetime.now(timezone.utc)

    # Calculate freshness in hours
    freshness_sources = []
    for time in update_times_sources:
        if time:
            freshness = (current_time - datetime.fromisoformat(time.replace('Z', '+00:00'))).total_seconds() / 3600
            freshness_sources.append(freshness)

    valid_freshness_sources = [value for value in freshness_sources if value >= 0]
    average_freshness_sources = (
        sum(valid_freshness_sources) / len(valid_freshness_sources) if valid_freshness_sources else 0
    )

    # Calculate completeness for sources
    completeness_fields_sources = [
        'provider', 'assessment', 'category', 'detect_time', 'update_time', 'status',
        'start_time', 'detected_by', 'sources'
    ]
    
    completeness_scores_sources = []
    for source in response_data.get('lookup_results', {}).get('sources', []):
        completeness_count = sum(1 for field in completeness_fields_sources if source.get(field))
        completeness_scores_sources.append(completeness_count / len(completeness_fields_sources) * 100)

    average_completeness_sources = (
        sum(completeness_scores_sources) / len(completeness_scores_sources) if completeness_scores_sources else 0
    )

    # Calculate relevance (same as for domains)
    relevance_fields = [
        'id', 'type', 'created', 'modified', 'name', 'description', 'labels', 'external_references',
        'object_marking_refs', 'source_name', 'created_by_ref', 'valid_from', 'valid_until',
        'kill_chain_phases', 'indicators', 'threat_actors', 'malware', 'attack_patterns',
        'courses_of_action', 'incident', 'infrastructure', 'sightings'
    ]
    relevance_scores = []
    for field in relevance_fields:
        relevance_count = 1 if response_data.get(field) else 0
        relevance_scores.append(relevance_count)

    average_relevance = sum(relevance_scores) / len(relevance_fields) * 100

    return {
        'freshness_sources': average_freshness_sources,
        'completeness_percentage': average_completeness_sources,
        'relevance_percentage': average_relevance,
        #'detected_by': detected_by  # Add detected_by for URLs
    }




# Function to process indicators (IP, Domain, Hash, URL)
def process_indicators(input_csv_path, output_csv_path, api_key):
    with open(input_csv_path, 'r') as csv_file:
        reader = csv.reader(csv_file)
        rows = list(reader)

    output_header = ['Indicator', 'Type', 'Freshness (hours since last update for sources)', 'Completeness Percentage', 'Relevance Percentage']
    output_data = []

    for row in rows:
        indicator = row[0]
        print(indicator)

        indicator_type = determine_indicator_type(indicator)
        print("Type:", indicator_type)

        if not indicator_type:
            print(f"Unknown indicator type for: {indicator}")
            continue

        
        if indicator_type == "url":
            encoded_url = quote(indicator, safe='')
            url = f'https://api.metadefender.com/v4/url/{encoded_url}'
        else:
            url = f'https://api.metadefender.com/v4/{indicator_type}/{indicator}'
        
        headers = {'apikey': api_key}
        
        # Implement retry mechanism and error handling for requests
        try:
            response = requests.get(url, headers=headers, timeout=10)  # Set a timeout
            print("Response:", response)
            response.raise_for_status()  # Raise an exception for HTTP error codes
            
            response_data = json.loads(response.text)
            print("Response Data:", response_data)
            analysis_result = analyze_metadefender_response(response_data, indicator_type)

            output_row = [
                indicator,
                indicator_type,
                analysis_result['freshness_sources'],
                #analysis_result['completeness_percentage_sources'],
                #analysis_result['completeness_percentage_geo'],
                analysis_result['completeness_percentage'],
                analysis_result['relevance_percentage']
            ]

            output_data.append(output_row)

        except requests.exceptions.RequestException as e:
            print(f"Error for {indicator_type} {indicator}: {e}")

    with open(output_csv_path, 'w', newline='') as output_csv_file:
        writer = csv.writer(output_csv_file)
        writer.writerow(output_header)
        writer.writerows(output_data)

if __name__ == "__main__":
    input_csv_path = 'Your input file.csv' # replace this with your input file that has IoCs
    output_csv_path = 'Your output file.csv' # replace this with your desired output file
    api_key = 'your_metadefender_api_key'  # Replace with your MetaDefender API key

    process_indicators(input_csv_path, output_csv_path, api_key)
