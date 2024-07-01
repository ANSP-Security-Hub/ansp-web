from schemas.map import CountryConnections
from schemas.device import Health

from processing.map import get_map_info
from processing.map_byip import get_map_info as get_map_info_by_ip
from services.devices import DeviceIdDB

from country_converter import CountryConverter


class MapService:
    __db = DeviceIdDB()
    __converter = CountryConverter()

    @classmethod
    def get_all_country_connections(cls) -> list[CountryConnections]:
        map_connections = get_map_info()

        result = []
        for country, total_count in map_connections.items():
            country_name = cls.get_country_name(country)
            if country_name in ['Local', 'Unknown']:
                continue
            result.append(
                CountryConnections(
                    country=country_name,
                    total_count=total_count,
                    count_by_status={Health.HEALTHY: total_count, Health.WARNING: 0, Health.CRITICAL: 0}
                )
            )
        return result

    @classmethod
    def get_country_connections_by_device(cls, device_id: str) -> list[CountryConnections]:
        device_ip = cls.__db.get_device_ip(device_id)
        if device_ip is None:
            return []

        map_connections = get_map_info_by_ip(device_ip)
        result = []
        for country, total_count in map_connections.items():
            country_name = cls.get_country_name(country)
            if country_name in ['Local', 'Unknown']:
                continue
            result.append(
                CountryConnections(
                    country=country_name,
                    total_count=total_count,
                    count_by_status={Health.HEALTHY: total_count, Health.WARNING: 0, Health.CRITICAL: 0}
                )
            )

        return result

    @staticmethod
    def get_country_name(country_code: str | None) -> str:
        if country_code is None:
            return 'Unknown'
        if country_code in ['Local', 'Unknown']:
            return country_code
        return MapService.__converter.convert(country_code, to='short_name')
