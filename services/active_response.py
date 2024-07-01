from data_sources.pi_hole_api import PiHoleApi


class ActiveResponseService:
    pihole = PiHoleApi()

    @classmethod
    def block_domain(cls, domain: str) -> bool:
        return cls.pihole.block_domain(domain)

    @classmethod
    def allow_domain(cls, domain: str) -> bool:
        return cls.pihole.allow_domain(domain)

    @classmethod
    def top_items(cls, number: int) -> tuple[str, str]:
        return cls.pihole.top_items(number)
