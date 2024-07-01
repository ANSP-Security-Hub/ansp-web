#!../venv/bin/python3

import sys

try:
    from wazuh_indexer_api import WazuhIndexer
    import config
except ImportError:
    from data_sources.wazuh_indexer_api import WazuhIndexer
    import processing.config as config

import socket

import ipaddress


def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False

def ip_to_domain(ip):
    try:
        domain = socket.gethostbyaddr(ip)
        return domain[0]
    except socket.herror:
        return "Unknown"

def websites_info(logs, n):
    info_dict = {}

    for log in logs:
        source = log.get('_source', {})
        data = source.get('data', {})
        content = data.get('content', {})
        dst_ip = log['_source']['data']['content'].get('dst_ip')
        dst_port = log['_source']['data']['content'].get('dst_port')
        src_ip = log['_source']['data']['content'].get('src_ip')
        src_port = log['_source']['data']['content'].get('src_port')
        # status = content.get('status')
        duration = int(content.get('duration'))
        octets = int(content.get('octets'))

        if dst_ip and not is_private_ip(dst_ip) and duration >= 0 and dst_port in [80, 443, 8080]:
            if dst_ip not in info_dict:
                info_dict[dst_ip] = {"total_bytes": 0, "total_connections": 0, "total_duration": 0, "domain": ' '}
            info_dict[dst_ip]["total_connections"] += 1
            info_dict[dst_ip]["total_bytes"] += octets
            info_dict[dst_ip]["total_duration"] += duration

        elif src_ip and not is_private_ip(src_ip) and duration >= 0 and src_port in [80, 443, 8080]:
            if src_ip not in info_dict:
                info_dict[src_ip] = {"total_bytes": 0, "total_connections": 0, "total_duration": 0, "domain": ' '}
            info_dict[src_ip]["total_connections"] += 1
            info_dict[src_ip]["total_bytes"] += octets
            info_dict[src_ip]["total_duration"] += duration

    sorted_info = sorted(info_dict.items(), key=lambda x: x[1]["total_connections"], reverse=True)
    return sorted_info[:n]


def get_top_sites(n):
    '''
    takes one argument (number (n))-- if it takes nothing or 2 argument -> exit(1)
    if there is data - > return dictionary that contains n number of websites information (sorted based on total connections):
    info_dict[public ip] = {
                    "total_bytes": total number of bytes
                    "total_connections": total number of connections
                    "total_duration": total number of duration
                    "domain": based on pihole then ip_to_domain func (if there is a match, domain is set to domain name,if not it will call ip_to_domain function,otherwise it is set to "unknown")
              }
    if there is no data it will return an empty dictionary
    '''
    indexer = WazuhIndexer()
    alerts = indexer.get_alerts_by_fields(
        relative_time_seconds=config.NETMON_TIME,
        match_fields_map={"decoder.name": "netmon", "data.content.status": "closed"}
    )

    info_dict = websites_info(alerts, n)
    info_dict = dict(info_dict)
    for ip in info_dict:
        #print(ip)
        indexer = WazuhIndexer()
        pihole_alerts = indexer.get_alerts_by_fields(
            relative_time_seconds=config.PIHOLE_TIME,
            match_fields_map={"decoder.name": "pihole", "data.extra_data": ip}
        )
        domain = None
        if pihole_alerts:
            for log in pihole_alerts:
                temp_domain = log['_source']['data']['data']
                if temp_domain:
                   domain=temp_domain
                   break
        if domain:
            info_dict[ip]['domain'] = domain
        else:
            info_dict[ip]['domain'] = ip_to_domain(ip)

    return dict(info_dict)


def main():

    if len(sys.argv) == 2:
        n=int(sys.argv[1])
    else:
        sys.exit(1)

    info_dict = get_top_sites(n)
    print(info_dict)


if __name__ == '__main__':
    main()
