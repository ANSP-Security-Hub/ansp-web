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


def num_of_dev(monitor, netmon):
        set_ids = set()
        set_ips = set()
        for log in monitor:
                source=log.get('_source',{})
                agent_id = source.get('id')
                agent_ip = source.get('ip')

                if agent_id:
                        set_ids.add(agent_id)
                        set_ips.add(agent_ip)
        private_ips = agentless_ips(netmon) #call the function(agentless)
        private_ips= (private_ips-set_ips) #extract agent from netmon
#print agent and agentless ip
#        print (private_ips)
#        print ()
#        print (set_ips)
        return len(set_ids)+len(private_ips)

def agentless_ips(netmon): #num of agentless devices (active or idle)
        private_ips = set()
        for log in netmon:
                source=log.get('_source', {})
                data=source.get('data', {})
                content = data.get('content', {})
                src_ip = content.get('src_ip')
                dst_ip = content.get('dst_ip')
                status = content.get('status')

                if is_private_ip(src_ip):
                     private_ips.add(src_ip)
                #if status in ['active', 'idle', 'closed']:
                #if src_ip.startswith("192.168.") or src_ip.startswith("10.") or src_ip.startswith("172."):
                #    private_ips.add(src_ip)
#                if dst_ip.startswith("192.168.") or dst_ip.startswith("10.") or dst_ip.startswith("172."):
#                    private_ips.add(dst_ip)
        return private_ips

def get_num_of_dev():
        '''
        if there is data -> return a dictionary that contain the number of devices:
        num_dict={'number':num}
        if not -> it will return an empty dictionary
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

        num = num_of_dev(monitor, netmon)
        num_dict={'number':num}
        #print(num_dict)
        return num_dict


def main():

        num_dict = get_num_of_dev()
        print(num_dict)

if __name__ == '__main__':
        main()


