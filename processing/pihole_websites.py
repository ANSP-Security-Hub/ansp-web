#!../venv/bin/python3

import sys
try:
        from wazuh_indexer_api import WazuhIndexer
        import config
except ImportError:
        from data_sources.wazuh_indexer_api import WazuhIndexer
        import processing.config as config

def pihole_sites(logs,n):
        pihole_replies = {}
        for log in logs:

                source=log.get('_source', {})
                data=source.get('data', {})
                domain=data.get('data')

                if domain in pihole_replies:
                        pihole_replies[domain] += 1
                else:
                        pihole_replies[domain] = 1
        sorted_pihole_replies = dict(sorted(pihole_replies.items(), key=lambda item: item[1], reverse=True))
        return dict(list(sorted_pihole_replies.items())[:n])


def get_pihole_sites(n):
        '''
        takes one argument (number (n))-- if it takes nothing or 2 argument -> exit(1)
        if there is data - > return dictionary that contains n number of websites information (sorted based on total connections):
        top_sites = {
                    "domain": domain name
                    "total_connections": total number of connections
              }
        if there is no data it will return an empty dictionary
        '''
        indexer = WazuhIndexer()
        alerts = indexer.get_alerts_by_fields(
                relative_time_seconds=config.PIHOLE_TIME,
                match_fields_map={"decoder.name": "pihole", "data.query_type": "reply"}
        )
        top_sites=pihole_sites(alerts,n)
        return top_sites

def main():
        if len(sys.argv) == 2:
                n=int(sys.argv[1])
        else:
                sys.exit(1)
        top_sites=get_pihole_sites(n)
        print(top_sites)


if __name__ == '__main__':
        main()
