import json
from datetime import datetime, timezone
import requests
import csv
import re

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
def analyze_metadefender_response(response_data):
    # Calculate freshness (time since last update) for sources
    update_times_sources = [source.get('update_time') for source in response_data.get('lookup_results', {}).get('sources', [])]
    current_time = datetime.now(timezone.utc)
    freshness_sources = [(current_time - datetime.fromisoformat(time.replace('Z', '+00:00'))).total_seconds() / 3600 for time in update_times_sources]

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

    average_freshness_sources = sum(freshness_sources) / len(freshness_sources) if freshness_sources else 0

    return {
        'freshness_sources': average_freshness_sources,
        'completeness_percentage_sources': average_completeness_sources,
        'completeness_percentage_geo': average_completeness_geo,
        'completeness_percentage_all': average_completeness_all,
        'relevance_percentage': average_relevance
    }

# Function to process indicators (IP, Domain, Hash, URL)
def process_indicators(input_csv_path, output_csv_path, api_key):
    with open(input_csv_path, 'r') as csv_file:
        reader = csv.reader(csv_file)
        rows = list(reader)

    output_header = ['Indicator', 'Type', 'Freshness (hours since last update for sources)', 'Completeness Percentage (Sources)', 'Completeness Percentage (Geo_info)', 'Average Completeness Percentage', 'Relevance Percentage']
    output_data = []

    for row in rows:
        indicator = row[0]
        print(indicator)

        indicator_type = determine_indicator_type(indicator)

        if not indicator_type:
            print(f"Unknown indicator type for: {indicator}")
            continue

        url = f'https://api.metadefender.com/v4/{indicator_type}/{indicator}'
        headers = {'apikey': api_key}
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            response_data = json.loads(response.text)
            analysis_result = analyze_metadefender_response(response_data)

            output_row = [
                indicator,
                indicator_type,
                analysis_result['freshness_sources'],
                analysis_result['completeness_percentage_sources'],
                analysis_result['completeness_percentage_geo'],
                analysis_result['completeness_percentage_all'],
                analysis_result['relevance_percentage']
            ]

            output_data.append(output_row)
        else:
            print(f"Error for {indicator_type} {indicator}: {response.status_code}, {response.text}")

    with open(output_csv_path, 'w', newline='') as output_csv_file:
        writer = csv.writer(output_csv_file)
        writer.writerow(output_header)
        writer.writerows(output_data)

if __name__ == "__main__":
    input_csv_path = 'IoC.csv'  # Replace with your input CSV file path
    output_csv_path = 'MD_output_stats.csv'  # Replace with your output CSV file path
    api_key = 'your_metadefender_api_key'  # Replace with your MetaDefender API key

    process_indicators(input_csv_path, output_csv_path, api_key)
