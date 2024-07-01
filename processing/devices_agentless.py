#!../venv/bin/python3
try:
    from wazuh_indexer_api import WazuhIndexer
    import config
except ImportError:
    from data_sources.wazuh_indexer_api import WazuhIndexer
    import processing.config as config

import ipaddress


def is_private_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def extract_agentless_info(monitor, netmon):
    agentless_info = {}
    set_ips = set()
    for log in monitor:
        source = log.get('_source', {})
        agent_ip = source.get('ip')
        if agent_ip:
            set_ips.add(agent_ip)  # agent ips
    for log in netmon:
        source = log.get('_source', {})
        data = source.get('data', {})
        content = data.get('content', {})
        src_ip = content.get('src_ip')
        dst_ip = content.get('dst_ip')
        status = content.get('status')
        last_conn = source.get('timestamp')
        if src_ip and src_ip not in set_ips and is_private_ip(src_ip) and status == "closed":
            agentless_info[src_ip] = {"status": "disconnected", "last_conn": last_conn[:10] + " " + last_conn[11:19]}

        elif src_ip and src_ip not in set_ips and is_private_ip(src_ip) and status in ["active", "idle"]:
            agentless_info[src_ip] = {"status": "active", "last_conn": "0"}

#        elif dst_ip and dst_ip not in set_ips and dst_ip.startswith(("192.168.", "10.", "172.")) and status == "closed":
#            agentless_info[dst_ip] = {"status": "disconnected", "last_conn": last_conn[:10] + " " + last_conn[11:19]}

#        elif dst_ip and dst_ip not in set_ips and dst_ip.startswith(("192.168.", "10.", "172.")) and status in ["active", "idle"]:
#            agentless_info[dst_ip] = {"status": "active", "last_conn": "0"}

    return agentless_info


def get_agentless_info():
    '''
    if there is a data -> return dictionary that contains the agentless information
    agentless_info[src_ip] = {
           "status": agent status -> active or disconnected
           "last_conn": last connected -> if active last_conn='0', if disconnected last_conn='(yyyy-mm-dd hh:mm:ss)'
     }
    if not it will return an empty dictionary
    '''
    indexer = WazuhIndexer(index_name="wazuh-monitoring*")
    monitor = indexer.get_alerts_by_fields(
        relative_time_seconds=config.MONITORING_TIME,
        match_fields_map={}
    )

    indexer = WazuhIndexer()
    netmon = indexer.get_alerts_by_fields(
        relative_time_seconds=config.NETMON_TIME,
        match_fields_map={"decoder.name": "netmon"}
    )

    agentless_info = extract_agentless_info(monitor, netmon)
    # print(agentless_info)
    return agentless_info


def main():
    agentless_info = get_agentless_info()
    print(agentless_info)


if __name__ == '__main__':
    main()
