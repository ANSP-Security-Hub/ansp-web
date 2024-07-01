#!../venv/bin/python3
import sys
try:
	from wazuh_indexer_api import WazuhIndexer
	import config
except ImportError:
	from data_sources.wazuh_indexer_api import WazuhIndexer
	import processing.config as config


def extract_agent_info_byip(monitor):
	"""
	Extracts agent information from Wazuh monitoring data.
	"""
	agent_info = {}
	for log in monitor:
		source = log.get('_source', {})
		device_id = source.get('id')
		device_name = source.get('name')
		device_ip = source.get('ip')
		os_name = source['os'].get('name')
		status = source.get('status')
		last_conn = source.get('lastKeepAlive')

		if device_id and device_name and device_ip and os_name and status: #all information exist
			if status == "disconnected":
				agent_info = {
					"name": device_name,
					"id": device_id,
					"os": os_name,
					"status": status,
					"last_conn": last_conn[:10] + " " + last_conn[11:19],
					'health': 'healthy',
					'alert_num': {'medium': 0, 'high': 0},
					'alerts': {'medium': [], 'high': []}
				}
			else:
				agent_info = {
					"name": device_name,
					"id": device_id,
					"os": os_name,
					"status": status,
					"last_conn": "0",
					'health': 'healthy',
					'alert_num': {'medium': 0, 'high': 0},
					'alerts': {'medium': [], 'high': []}
				}
	return agent_info

def agent_alerts_byip(alerts, agent_info, ip):
	"""
	Calculates agent health based on alerts.
	"""
	for log in alerts:
		source = log.get('_source', {})
		agent = source.get('agent', {})
		agent_ip = agent.get('ip')
		rule = source.get('rule', {})
		rule_level = rule.get('level')

		if agent_ip==ip:
			if 6 < rule_level <= 10:
				agent_info['alert_num']['medium'] += 1
				agent_info['alerts']['medium'].append(log)
			elif rule_level > 10:
				agent_info['alert_num']['high'] += 1
				agent_info['alerts']['high'].append(log)

	for agent_ip in agent_info:
		if agent_info['alert_num']['high'] > 0:
			agent_info['health'] = 'critical'
		elif agent_info['alert_num']['medium'] > 500:
			agent_info['health'] = 'critical'
		elif agent_info['alert_num']['medium'] > 50:
			agent_info['health'] = 'warning'
		else:
			agent_info['health'] = 'healthy'

	return agent_info


def get_agent_info_byip(ip):
	"""
	takes one argument (ip)-- if it takes nothing or 2 argument -> exit(1)
	if there is data - > return dictionary that conatins one agent information:
    	 agent_info= {
                    "name": agent name
                    "id": agent id,
                    "os": os name,
                    "status": agent status -> active or disconnected
                    "last_conn":last connected -> if active last_conn='0', if disconnected last_conn='(yyyy-mm-dd hh:mm:ss)'
                    "health": agent health -> (healthy, warning, critical)
						-if medium alerts between 50 and 500 (warning)
						-if medium alerts greater than 500 (critical)
						-if high alerts greater than 0 (critical)
						-else (healthy)

                    "alert_num": {
                                "medium": num of medium alerts
                                 "high": num of high alerts
                       }  (if there is no alert for the specific ip {medium=0, high=0})

                    "alerts": {
                                "medium": list of medium alerts(full log)
                                 "high": list of high alerts(full log)
                       } (if there is no alert for the specific ip {medium: empty list, high:empty list})
           }

    	if there is no data or invalid argument it will return an empty dictionary
	"""
	indexer = WazuhIndexer(index_name="wazuh-monitoring*")
	monitor = indexer.get_alerts_by_fields(
		relative_time_seconds=config.MONITORING_TIME,
		match_fields_map={'ip': ip}
	)

	indexer = WazuhIndexer()
	alerts = indexer.get_alerts_by_fields(
		relative_time_seconds=config.ALL_ALERTS_TIME,
		range_fields_map={"rule.level": {"gte": 7}}
	)
	agent_info = extract_agent_info_byip(monitor) #call the fun
	agent_info = agent_alerts_byip(alerts, agent_info, ip)

	return agent_info

def main():
	if len(sys.argv) != 2:
		sys.exit(1)

	ip = sys.argv[1]
	agent_info=get_agent_info_byip(ip)
	print(agent_info)

if __name__ == '__main__':
	main()
