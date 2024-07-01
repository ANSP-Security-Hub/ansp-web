import time

from schemas.device import DeviceDetails, Health, Status


# from utils import get_hash

def get_hash(ip: str) -> str:
    """
    Generate a unique hash for the device.
    """
    return str(abs(hash(ip)))[:16]


arr = [
    DeviceDetails(
        id=get_hash("192.168.1.10"),
        name="Device 1",
        ip="192.168.1.10",
        health=Health.HEALTHY,
        status=Status.ACTIVE,
        last_connected=0,
        os="Windows",
        uptime=60 * 60 * 3,
        used_bandwidth=1024 ** 2 * 1.5

    ),
    DeviceDetails(
        id=get_hash("192.168.1.11"),
        name="Device 2",
        ip="192.168.1.11",
        health=Health.WARNING,
        status=Status.ACTIVE,
        last_connected=0,
        os="Linux",
        uptime=60 * 60 * 24 * 2,
        used_bandwidth=1024 ** 2 * 2.5
    ),
    DeviceDetails(
        id=get_hash("192.168.1.12"),
        name="Device 3",
        ip="192.168.1.12",
        health=Health.HEALTHY,
        status=Status.DISCONNECTED,
        last_connected=int(time.time()) - 60 * 60,
        os="Mac",
        uptime=0,
        used_bandwidth=0,
    ),
    DeviceDetails(
        id=get_hash("192.168.1.13"),
        name="Device 4",
        ip="192.168.1.13",
        health=Health.CRITICAL,
        status=Status.ACTIVE,
        last_connected=0,
        os="Windows",
        uptime=60 * 60 * 13,
        used_bandwidth=1024 ** 2 * 3.5
    )
]


def get_device_details(id: str) -> DeviceDetails:
    """
    Fetch device details from the database.
    """
    return next((device for device in arr if device.id == id), None)
