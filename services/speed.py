from random import random

from schemas.speed import Speed
from processing.speed import get_network_speed


class SpeedService:
    @staticmethod
    def get_speed() -> Speed:
        # return Speed(download_speed=get_network_speed() * 1024 * 1024)
        # random between 50 and 70 mbps
        return Speed(download_speed=(50 + random() * 20) * 1024 ** 2)

