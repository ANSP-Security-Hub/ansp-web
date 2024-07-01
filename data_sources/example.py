#!./venv/bin/python3
import json

from data_sources.wazuh_indexer_api import WazuhIndexer




def main():
    indexer = WazuhIndexer()

    alerts = indexer.get_alerts_by_fields(
        relative_time_seconds=60*60,
        field_phrases_map={"decoder.name": "netmon"}
    )

    if alerts:
        print(json.dumps(alerts, indent=2))


if __name__ == '__main__':
    main()

