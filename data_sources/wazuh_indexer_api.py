#!./venv/bin/python3
import json

import requests
from datetime import datetime, timedelta
import urllib3
from dotenv import load_dotenv
import os

# Suppress InsecureRequestWarning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load environment variables from .env file
load_dotenv()


class WazuhIndexer:
    def __init__(self, base_url='https://127.0.0.1:9200', index_name='wazuh-alerts*'):
        self.base_url = base_url
        self.index_name = index_name
        self.auth = (os.getenv("WAZUH_USERNAME"), os.getenv("WAZUH_PASSWORD"))
        self.headers = {'Content-Type': 'application/json'}

    def get_mapping(self):
        url = f"{self.base_url}/{self.index_name}/_mapping"
        try:
            response = requests.get(url, auth=self.auth, headers=self.headers, verify=False)
            response.raise_for_status()  # Raise an exception for 4xx and 5xx status codes
            mapping = response.json()
            return mapping
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error occurred: {e}")
            return None

    def get_alerts_by_fields(self,
                             relative_time_seconds: int,
                             match_fields_map: dict[str, str] = {},
                             range_fields_map: dict[str, dict[str, str | int]] = {},
                             size=1000
                             ) -> list[dict]:
        """
        Get alerts from Wazuh indexer based on field phrases and relative time.
        :param relative_time_seconds: Time range in seconds (e.g., 3600 for last hour)
        :param match_fields_map: A dictionary of field names and phrases to match (e.g., {"decoder.name": "ntopng"})
        :param range_fields_map: A dictionary of field names and ranges to match (e.g., {"rule.level": {"gte": 7, "lt": 10}})
        :param size: Maximum number of alerts to return
        :return:  A list of alerts matching the criteria (same as Wazuh Discover - alert JSON view)
        """
        url = f'{self.base_url}/{self.index_name}/_search'

        # Calculate time range based on relative_time
        end_time = datetime.now()
        start_time = end_time - timedelta(seconds=relative_time_seconds)

        # Convert start and end times to epoch milliseconds
        # start_time_ms = int(start_time.timestamp() * 1000)
        # end_time_ms = int(end_time.timestamp() * 1000)

        # Convert start and end times to ISO 8601 format
        start_time_iso = start_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        end_time_iso = end_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # Construct the query dynamically
        must_queries = []
        for field, phrase in match_fields_map.items():
            must_queries.append({"match_phrase": {field: phrase}})

        for field, range_map in range_fields_map.items():
            must_queries.append({"range": {field: range_map}})

        data = {
            "from": 0,
            "size": size,
            "query": {
                "bool": {
                    "must": must_queries,
                    "filter": [
                        {"match_all": {}},
                        {
                            "range": {
                                "timestamp": {
                                    "gte": start_time_iso,
                                    "lte": end_time_iso
                                }
                            }
                        }
                    ],
                    "should": [],
                    "must_not": []
                }
            }
        }

        try:
            response = requests.post(url, headers=self.headers, auth=self.auth, json=data, verify=False)
            response.raise_for_status()  # Raise an exception for 4xx and 5xx status codes
            result = response.json()
            result = result['hits']['hits']
            return result
        except requests.exceptions.HTTPError as e:
            print(f"HTTP error occurred: {e}")
            return None


if __name__ == '__main__':
    index = WazuhIndexer(index_name='wazuh-alerts*')
    relative_time_seconds = 360000  # Last hour
    field_phrases_map = {
        "decoder.name": "netmon"
        # "data.content.dst_ip": "10.10.10.1"
    }

    alerts = index.get_alerts_by_fields(
        relative_time_seconds,
        # match_fields_map=field_phrases_map,
        range_fields_map={"rule.level": {"gte": 7}},
        size=1
    )
    if alerts:
        print(json.dumps(alerts))
    else:
        print("Failed to retrieve alerts.")
