from datetime import datetime
from typing import Literal, Optional

from schemas.device import Device, Health, Status, DeviceDetails

from processing.devices_agent import get_agent_info
from processing.devices_agentless import get_agentless_info
from processing.devices_agent_byip import get_agent_info_byip
from processing.devices_agentless_byip import get_agentless_info_byip
from processing.agentless_health import AgentlessHealth
import hashlib


class DeviceIdDB:
    shared = {}

    def __init__(self):
        self.db = self.shared

    def add_device(self,
                   device_id: str,
                   device_ip: str,
                   device_type: Literal["agent", "agentless"],
                   device_name: Optional[str] = None,
                   agent_id: Optional[str] = None
                   ):
        self.db[device_id] = {
            "id": device_id,  # "id" is redundant, but it's here for consistency with the other fields
            "ip": device_ip,
            "type": device_type,
            "name": device_name,
            "agent_id": agent_id
        }

    def get_device_ip(self, device_id: str) -> str | None:
        return self.db.get(device_id, {}).get("ip", None)

    def get_device_type(self, device_id: str) -> Literal["agent", "agentless"] | None:
        return self.db.get(device_id, {}).get("type", None)

    def get_device_name(self, device_id: str) -> str | None:
        return self.db.get(device_id, {}).get("name", None)

    def get_agent_id(self, device_id: str) -> str | None:
        return self.db.get(device_id, {}).get("agent_id", None)

    def get_device_details(self, device_id: str) -> dict:
        return self.db.get(device_id, None)


class DeviceService:
    __db = DeviceIdDB()
    agentless_health_processor = AgentlessHealth()

    @classmethod
    def get_devices(cls) -> list[Device]:
        agent_devices = cls.__get_agent_devices()
        agentless_devices = cls.__get_agentless_devices()
        return agent_devices + agentless_devices

    @classmethod
    def get_device_details(cls, device_id: str) -> DeviceDetails | None:
        device_from_db = cls.__db.get_device_details(device_id)
        if not device_from_db:
            return None

        device_type = cls.__db.get_device_type(device_id)
        if device_type == "agent":
            return cls.__get_agent_details(device_from_db)
        elif device_type == "agentless":
            return cls.__get_agentless_details(device_from_db)
        return None

    # PRIVATE METHODS
    @classmethod
    def __get_id(cls,
                 device_ip: str,
                 device_type: Literal["agent", "agentless"],
                 device_name: Optional[str] = None,
                 agent_id: Optional[str] = None
                 ) -> str:
        device_id = cls.__get_hash(device_ip)
        cls.__db.add_device(device_id, device_ip, device_type, device_name, agent_id)
        return device_id

    @classmethod
    def __get_agent_devices(cls) -> list[Device]:
        agent_devices = get_agent_info()
        devices = []
        for ip, device in agent_devices.items():
            device_name = f"Agent - {device['name']}"
            device_id = cls.__get_id(ip, "agent", device_name, device["id"])

            status = Status(device["status"])
            if status == Status.DISCONNECTED:
                last_connected = cls.__last_connected_to_timestamp(device["last_conn"])
                uptime = None
            else:
                last_connected = None
                # uptime = cls.__uptime_to_seconds(device["uptime"])
                uptime = 0  # TODO: waiting for uptime data to be available
            devices.append(Device(
                id=device_id,
                name=device_name,
                ip=ip,
                health=Health(device.get("health", "unknown")),
                status=status,
                uptime=uptime,
                last_connected=last_connected
            ))
        return devices

    @classmethod
    def __get_agentless_devices(cls) -> list[Device]:
        agentless_devices = get_agentless_info()
        health = cls.agentless_health_processor.get_devices_health_multi_requests(list(agentless_devices.keys()))
        devices = []
        count = 0
        for ip, device in agentless_devices.items():
            count += 1
            device_name = f"Agentless - {count}"
            device_id = cls.__get_id(ip, "agentless", device_name)
            status = Status(device["status"])
            if status == Status.DISCONNECTED:
                last_connected = cls.__last_connected_to_timestamp(device["last_conn"])
                uptime = None
            else:
                last_connected = None
                # uptime = cls.__uptime_to_seconds(device["uptime"])
                uptime = 0  # TODO: waiting for uptime data to be available
            devices.append(Device(
                id=device_id,
                name=device_name,
                ip=ip,
                health=Health(health.get(ip, 'unknown')),
                status=status,
                uptime=uptime,
                last_connected=last_connected
            ))

        # sort on ip
        devices.sort(key=lambda x: x.ip)
        return devices

    @classmethod
    def __get_agent_details(cls, device_from_db: dict) -> DeviceDetails | None:
        agent_info = get_agent_info_byip(device_from_db["ip"])
        if not agent_info:
            return None

        return DeviceDetails(
            id=device_from_db["id"],
            name=device_from_db["name"],
            ip=device_from_db["ip"],
            health=Health(agent_info.get('health', 'unknown')),
            status=Status(agent_info["status"]),
            last_connected=cls.__last_connected_to_timestamp(agent_info["last_conn"]),
            uptime=0,  # TODO
            os=agent_info["os"],
            used_bandwidth=0,  # TODO
            top_sites=None,  # TODO
            alert_count=agent_info.get('alert_num'),
            alerts=agent_info.get('alerts')
        )

    @classmethod
    def __get_agentless_details(cls, device_from_db: dict) -> DeviceDetails | None:
        ip = device_from_db["ip"]
        agentless_info = get_agentless_info_byip(ip)
        health = cls.agentless_health_processor.get_device_health(ip) or 'unknown'
        alerts_count = cls.agentless_health_processor.get_device_alerts_num(ip)
        alerts = cls.agentless_health_processor.get_device_alerts_levels(ip)
        if not agentless_info:
            return None

        return DeviceDetails(
            id=device_from_db["id"],
            name=device_from_db["name"],
            ip=ip,
            health=Health(health),
            status=Status(agentless_info["status"]),
            last_connected=cls.__last_connected_to_timestamp(agentless_info["last_conn"]),
            uptime=0,  # TODO
            os="Unknown",  # TODO
            used_bandwidth=0,  # TODO
            top_sites=None,  # TODO
            alerts=alerts,
            alert_count=alerts_count
        )

    @staticmethod
    def __last_connected_to_timestamp(last_connected: str) -> int:
        try:
            return int(datetime.strptime(last_connected, "%Y-%m-%d %H:%M:%S")
                       .timestamp())
        except ValueError:
            return 0

    @staticmethod
    def __uptime_to_seconds(uptime: str) -> int:
        try:
            return int(uptime)
        except ValueError:
            return 0

    @staticmethod
    def __get_hash(text: str):
        return hashlib.sha256(text.encode()).hexdigest()[:16]

# mock_devices = [
#     Device(
#         id=DeviceService.("192.168.1.10"),
#         name="Device 1",
#         ip="192.168.1.10",
#         health=Health.HEALTHY,
#         status=Status.ACTIVE,
#         last_connected=0
#     ),
#     Device(
#         id=get_hash("192.168.1.11"),
#         name="Device 2",
#         ip="192.168.1.11",
#         health=Health.WARNING,
#         status=Status.ACTIVE,
#         last_connected=0
#     ),
#     Device(
#         id=get_hash("192.168.1.12"),
#         name="Device 3",
#         ip="192.168.1.12",
#         health=Health.HEALTHY,
#         status=Status.DISCONNECTED,
#         last_connected=int(time.time()) - 60 * 60
#     ),
#     Device(
#         id=get_hash("192.168.1.13"),
#         name="Device 4",
#         ip="192.168.1.13",
#         health=Health.CRITICAL,
#         status=Status.ACTIVE,
#         last_connected=0
#     )
# ]
