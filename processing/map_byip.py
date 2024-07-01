#!../venv/bin/python3

import sys
try:
        from wazuh_indexer_api import WazuhIndexer
        import config
except ImportError:
        from data_sources.wazuh_indexer_api import WazuhIndexer
        import processing.config as config

def extract_map_info(alerts, ip):
# Extracting country names and total octets for each country from all logs
        ip_data = {}
        for log in alerts:
                source = log.get('_source', {})
                data = source.get('data', {})
                content = data.get('content', {})
                sr_data=content.get("src_data", {})
                ds_data=content.get("dst_data", {})
                src_country = sr_data.get("country")
                dst_country = ds_data.get('country')
                octets = int(content.get('octets'))
                src_ip=content.get('src_ip')
                dst_ip=content.get('dst_ip')


                if src_ip == ip:
                    if dst_country not in ip_data:
                        ip_data[dst_country] = 0
                    ip_data[dst_country] += 1

                if dst_ip == ip:
                    if src_country not in ip_data:
                        ip_data[src_country] = 0
                    ip_data[src_country] += 1

        return ip_data

def get_map_info(ip):
        '''
        takes one argument (ip)-- if it takes nothing or 2 argument -> exit(1)
        if there is data - > return dictionary that conatins countries and number of bytes for each counrty for specific device(ip)
            country_octets = { country name : number of bytes, country name : number of bytes, .... }
        if there is no data or invalid argument it will return an empty dictionary
        '''
        indexer = WazuhIndexer()
        alerts = indexer.get_alerts_by_fields(
                relative_time_seconds=config.NETMON_TIME,
                match_fields_map={"decoder.name": "netmon"}
        )

        map = extract_map_info(alerts, ip)
        return map

def main():
        if len(sys.argv) != 2:
                sys.exit(1)

        ip = sys.argv[1]

        map = get_map_info(ip)
        print(map)

if __name__ == '__main__':
        main()
