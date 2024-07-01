#!./venv/bin/python3
import json

try:
    from wazuh_indexer_api import WazuhIndexer
except ImportError:
    from data_sources.wazuh_indexer_api import WazuhIndexer


def main():
    indexer = WazuhIndexer(index_name="wazuh-moni*")

    alerts = indexer.get_alerts_by_fields(
        relative_time_seconds=60 * 60,
        field_phrases_map={"ip": "10.10.10.1"},
        size=2
    )

    if alerts:
        print(json.dumps(alerts, indent=2))


if __name__ == '__main__':
    main()
