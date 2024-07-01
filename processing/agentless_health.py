#!../venv/bin/python3
import json
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


try:
    from wazuh_indexer_api import WazuhIndexer
    import config
except ImportError:
    from data_sources.wazuh_indexer_api import WazuhIndexer
    import processing.config as config




class AlertLog(BaseModel):
    src_ip: str
    dest_ip: str
    log_source: str
    log_description: str
    rule_description: Optional[str]
    rule_level: int
    rule_id: str
    rule_groups: list[str]
    timestamp: int
    full_log: str


class AgentlessHealth:
    log_sources = [
        "ntopng",
        "suricata",
        "pf"
    ]

    ALERT_MEDIUM_THRESHOLD = 6
    ALERT_HIGH_THRESHOLD = 10

    HEALTH_DEFAULT_DURATION = 60 * 60 * 24  # 24 hours

    HEALTH_WARNING_THRESHOLD = {
        "low": 50,
        "medium": 10,
        "high": 0
    }
    HEALTH_CRITICAL_THRESHOLD = {
        "low": 10000,
        "medium": 100,
        "high": 10
    }

    def __init__(self, relative_time: int = HEALTH_DEFAULT_DURATION):
        self.indexer = WazuhIndexer()
        self.logs: list[AlertLog] = []
        self.relative_time = relative_time

    def get_device_alerts_levels(self, ip: str) -> dict[str, list[AlertLog]]:
        alerts = self.__get_device_alerts(ip)
        return self.__get_alert_levels(alerts)

    def get_devices_health_multi_requests(self, ips: list[str]) -> dict[str, str]:
        devices_health = {}
        for ip in ips:
            devices_health[ip] = self.get_device_health(ip)
        return devices_health

    def get_device_health(self, ip: str) -> str:
        alert_num = self.get_device_alerts_num(ip)
        return self.__get_health(alert_num)

    def get_devices_health(self, ips: list[str]) -> dict[str, str]:
        devices_health = {}

        for ip in ips:
            alert_num = self.get_device_alerts_num(ip)
            devices_health[ip] = self.__get_health(alert_num)

        return devices_health

    def get_device_alerts_num(self, ip: str) -> dict[str, int]:
        return self.get_devices_alerts_num([ip]).get(ip, {})

    def get_devices_alerts_num(self, ips: list[str]) -> dict[str, dict[str, int]]:
        devices_alerts = self.__get_devices_alerts(ips)
        devices_alerts_levels = {}

        for ip, alerts in devices_alerts.items():
            devices_alerts_levels[ip] = self.__get_alert_levels_num(alerts)

        # print(devices_alerts_levels)
        return devices_alerts_levels

    def __get_health(self, alert_levels: dict[str, int]) -> str:
        if alert_levels["high"] > self.HEALTH_CRITICAL_THRESHOLD["high"]:
            return "critical"
        elif alert_levels["medium"] > self.HEALTH_CRITICAL_THRESHOLD["medium"]:
            return "critical"
        elif alert_levels["low"] > self.HEALTH_CRITICAL_THRESHOLD["low"]:
            return "critical"
        elif alert_levels["high"] > self.HEALTH_WARNING_THRESHOLD["high"]:
            return "warning"
        elif alert_levels["medium"] > self.HEALTH_WARNING_THRESHOLD["medium"]:
            return "warning"
        elif alert_levels["low"] > self.HEALTH_WARNING_THRESHOLD["low"]:
            return "warning"
        else:
            return "healthy"

    @classmethod
    def __get_alert_levels(cls, alerts: list[AlertLog]) -> dict[str, list[AlertLog]]:
        alert_levels = {
            "low": [],
            "medium": [],
            "high": []
        }
        for alert in alerts:
            if alert.rule_level < cls.ALERT_MEDIUM_THRESHOLD:
                alert_levels["low"].append(alert)
            elif alert.rule_level < cls.ALERT_HIGH_THRESHOLD:
                alert_levels["medium"].append(alert)
            else:
                alert_levels["high"].append(alert)
        return alert_levels

    @classmethod
    def __get_alert_levels_num(cls, alerts):
        alert_levels = {
            "low": 0,
            "medium": 0,
            "high": 0
        }
        for alert in alerts:
            if alert.rule_level < cls.ALERT_MEDIUM_THRESHOLD:
                alert_levels["low"] += 1
            elif alert.rule_level < cls.ALERT_HIGH_THRESHOLD:
                alert_levels["medium"] += 1
            else:
                alert_levels["high"] += 1
        return alert_levels

    def __get_device_alerts(self, ip: str) -> list[AlertLog]:
        return self.__get_devices_alerts([ip]).get(ip, [])

    def __get_devices_alerts(self, ips: list[str]) -> dict[str, list[AlertLog]]:
        devices_alerts = {}

        self.__add_alerts(devices_alerts, self.__get_alerts_ntopng(ips))
        self.__add_alerts(devices_alerts, self.__get_alerts_pf(ips))
        self.__add_alerts(devices_alerts, self.__get_alerts_suricata(ips))

        return devices_alerts

    def __get_alerts_base(self, decoder: str, ip_field_name: str, extra_match_fields: dict = None,
                          ips: list[str] = None) -> dict[str, list[dict]]:
        match_fields = {
            "decoder.name": decoder,
        }

        if len(ips) == 1:
            match_fields[ip_field_name] = ips[0]

        if extra_match_fields:
            match_fields.update(extra_match_fields)

        alerts = self.indexer.get_alerts_by_fields(
            relative_time_seconds=self.relative_time,
            match_fields_map=match_fields
        )

        result = {}
        if len(ips) > 1:
            for ip in ips:
                result[ip] = []
                # data.srcip -> ['data', 'srcip'], data.content.src_ip -> ['data', 'content', 'src_ip']
                for alert in alerts:
                    # get nested field value
                    ip_field_value = self.get_nested_field_value(alert, ip_field_name)

                    if ip_field_value == ip:
                        result[ip].append(alert)


        else:
            result[ips[0]] = alerts

        return result

    def __get_alerts_ntopng(self, ips: list[str]) -> dict[str, list[AlertLog]]:
        devices_alerts = self.__get_alerts_base(
            decoder="ntopng",
            ip_field_name="data.srcip",
            ips=ips,
            extra_match_fields={"data.type": "Flow"}
        )

        dst_alerts = self.__get_alerts_base(
            decoder="ntopng",
            ip_field_name="data.dstip",
            ips=ips,
            extra_match_fields={"data.type": "Flow"}

        )
        self.__add_alerts(devices_alerts, dst_alerts)

        schema = {
            "src_ip": "data.srcip",
            "dest_ip": "data.dstip",
            "log_source": "decoder.name",
            "log_description": "data.description",
            "rule_description": "rule.description",
            "rule_level": "rule.level",
            "rule_id": "rule.id",
            "rule_groups": "rule.groups",
            "timestamp": "timestamp",
            "full_log": "full_log"
        }

        result = {}
        for ip, devices_alerts in devices_alerts.items():
            result[ip] = self.__wazuh_alerts_to_alert_logs(devices_alerts, schema)
        return result

    def __get_alerts_pf(self, ips: list[str]) -> dict[str, list[AlertLog]]:
        devices_alerts = self.__get_alerts_base(
            decoder="pf",
            ip_field_name="data.srcip",
            ips=ips
        )

        dst_alerts = self.__get_alerts_base(
            decoder="pf",
            ip_field_name="data.dstip",
            ips=ips
        )
        self.__add_alerts(devices_alerts, dst_alerts)

        schema = {
            "src_ip": "data.srcip",
            "dest_ip": "data.dstip",
            "log_source": "decoder.name",
            "log_description": "data.protocol",
            "rule_description": "rule.description",
            "rule_level": "rule.level",
            "rule_id": "rule.id",
            "rule_groups": "rule.groups",
            "timestamp": "timestamp",
            "full_log": "full_log"
        }

        result = {}
        for ip, devices_alerts in devices_alerts.items():
            result[ip] = self.__wazuh_alerts_to_alert_logs(devices_alerts, schema)

        return result

    def __get_alerts_suricata(self, ips: list[str]) -> dict[str, list[AlertLog]]:
        devices_alerts = self.__get_alerts_base(
            decoder="json",
            ip_field_name="data.src_ip",
            ips=ips,
            extra_match_fields={"rule.groups": "suricata"}
        )

        dst_alerts = self.__get_alerts_base(
            decoder="json",
            ip_field_name="data.dest_ip",
            ips=ips,
            extra_match_fields={"rule.groups": "suricata"}
        )
        self.__add_alerts(devices_alerts, dst_alerts)

        schema = {
            "src_ip": "data.src_ip",
            "dest_ip": "data.dest_ip",
            "log_source": "decoder.name",
            "log_description": "data.alert.signature",
            "rule_description": "rule.description",
            "rule_level": "rule.level",
            "rule_id": "rule.id",
            "rule_groups": "rule.groups",
            "timestamp": "timestamp",
            "full_log": "data"
        }

        result = {}
        for ip, devices_alerts in devices_alerts.items():
            result[ip] = self.__wazuh_alerts_to_alert_logs(devices_alerts, schema)

        return result

    @staticmethod
    def __add_alerts(alerts: dict[str, list], new_alerts: dict[str, list]):
        for ip, new_alerts_list in new_alerts.items():
            if ip in alerts:
                alerts[ip].extend(new_alerts_list)
            else:
                alerts[ip] = new_alerts_list

    @staticmethod
    def __wazuh_alerts_to_alert_logs(alerts: list[dict], schema: dict) -> list[AlertLog]:
        result = []
        for alert in alerts:
            log = {}
            for key, alert_key in schema.items():
                value = AgentlessHealth.get_nested_field_value(alert, alert_key)
                if isinstance(value, dict):
                    value = json.dumps(value)

                log[key] = value

            log['timestamp'] = AgentlessHealth.__iso_timestamp_to_epoch(log['timestamp'])
            try:
                result.append(AlertLog(**log))
            except Exception as e:
                print(f"Error: {e}")
                print(log)
                print(alert)
                raise e

        return result

    @staticmethod
    def get_nested_field_value(alert, field_name, default=None, top_level='_source'):
        field_name = field_name.split(".")
        field_value = alert[top_level]
        for field in field_name:
            field_value = field_value.get(field, {})
            if not field_value:
                return default
        return field_value

    @staticmethod
    def __iso_timestamp_to_epoch(iso_timestamp: str) -> int:
        return int(datetime.fromisoformat(iso_timestamp[:-5]).timestamp())  # remove '+0000' because of error


if __name__ == '__main__':
    agentless_health = AgentlessHealth()
    # res = agentless_health.get_alerts_base(
    #     decoder="ntopng",
    #     ip_field_name="data.srcip",
    #     ips=["10.10.9.2", "192.168.1.2"],
    #     extra_fields={"data.type": "Flow"}
    # )
    #
    # res.update(agentless_health.get_alerts_base(
    #     decoder="ntopng",
    #     ip_field_name="data.dstip",
    #     ips=["10.10.9.2", "192.168.1.2"],
    #     extra_fields={"data.type": "Flow"}
    # )
    # )

    res = agentless_health.get_devices_health_multi_requests(["10.10.9.2", "192.168.1.1", "10.10.10.1"])

    print(json.dumps(res, indent=4))
