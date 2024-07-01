#!../venv/bin/python3

try:
	from wazuh_indexer_api import WazuhIndexer
	import config
except ImportError:
	from data_sources.wazuh_indexer_api import WazuhIndexer
	import processing.config as config


def extract_agent_info(monitor):
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
				agent_info[device_ip] = {
					"name": device_name,
					"id": device_id,
					"os": os_name,
					"status": status,
					"last_conn": last_conn[:10] + " " + last_conn[11:19],
					'health': 'healthy'
				}
			else:
				agent_info[device_ip] = {
					"name": device_name,
					"id": device_id,
					"os": os_name,
					"status": status,
					"last_conn": "0",
					'health': 'healthy'
				}
	return agent_info

def agent_alerts(alerts, agent_info):
	"""
	Calculates agent health based on alerts.
	"""
	c = {}
	for log in alerts:
		source = log.get('_source', {})
		agent = source.get('agent', {})
		agent_ip = agent.get('ip')
		rule = source.get('rule', {})
		rule_level = rule.get('level')

		if agent_ip:
			if agent_ip not in c:
				c[agent_ip] = {'medium': 0, 'high': 0}
			if 6 < rule_level <= 10:
				c[agent_ip]['medium'] += 1
			elif rule_level > 10:
				c[agent_ip]['high'] += 1

	for agent_ip in agent_info:
		if agent_ip in c:
			if c[agent_ip]['high'] > 0:
				agent_info[agent_ip]['health'] = 'critical'
			elif c[agent_ip]['medium'] > 500:
                                agent_info[agent_ip]['health'] = 'critical'
			elif c[agent_ip]['medium'] > 50:
				agent_info[agent_ip]['health'] = 'warning'
			else:
				agent_info[agent_ip]['health'] = 'healthy'

	return agent_info


def get_agent_info():
	"""
	if there is data - > return dictionary that conatins the agent information:
    	 agent_info[device_ip]= {
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
                 }
    	if not it will return an empty dictionary
	"""
	indexer = WazuhIndexer(index_name="wazuh-monitoring*")
	monitor = indexer.get_alerts_by_fields(
		relative_time_seconds=config.MONITORING_TIME,
		match_fields_map={}
	)

	indexer = WazuhIndexer()
	alerts = indexer.get_alerts_by_fields(
		relative_time_seconds=config.ALL_ALERTS_TIME,
		range_fields_map={"rule.level": {"gte": 7}}
	)
	agent_info = extract_agent_info(monitor) #call the fun
	agent_info = agent_alerts(alerts, agent_info)

	return agent_info

def main():
	agent_info = get_agent_info()
	print(agent_info)

if __name__ == '__main__':
	main()
