#!../venv/bin/python3

try:
        from wazuh_indexer_api import WazuhIndexer
        import config
except ImportError:
        from data_sources.wazuh_indexer_api import WazuhIndexer
        import processing.config as config

def extract_map_info(alerts):
# Extracting country names and total octets for each country from all logs
        country_octets = {}
        for log in alerts:
                source = log.get('_source', {})
                data = source.get('data', {})
                content = data.get('content', {})
                sr_data=content.get("src_data", {})
                ds_data=content.get("dst_data", {})
                src_country = sr_data.get("country")
                dst_country = ds_data.get('country')
                octets = int(content.get('octets'))

                if src_country not in country_octets:
                    country_octets[src_country] = 0
                country_octets[src_country] += 1

                if dst_country not in country_octets:
                    country_octets[dst_country] = 0
                country_octets[dst_country] += 1

                #country_octets[src_country] = country_octets.get(src_country, 0) + octets
                #country_octets[dst_country] = country_octets.get(dst_country, 0) + octets

        return country_octets


def get_map_info():
        '''
        if there is data - > return dictionary that conatins countries and number of bytes for each counrty for all devices
            country_octets = { country name : number of bytes, country name : number of bytes, .... }
        if there is no data it will return an empty dictionary
        '''
        indexer = WazuhIndexer()
        alerts = indexer.get_alerts_by_fields(
                relative_time_seconds=config.NETMON_TIME,
                match_fields_map={"decoder.name": "netmon"}
        )

        map = extract_map_info(alerts)
        return map

def main():
        map = get_map_info()
        print(map)

if __name__ == '__main__':
        main()

