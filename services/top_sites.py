from processing.top_sites import get_top_sites as get_top_websites
from processing.pihole_websites import get_pihole_sites as dns_get_top_websites

from schemas.website import Site


class SiteService:

    @staticmethod
    def get_top_sites(num: int) -> list[Site]:
        """
        Function to fetch the top N sites visited by users.
        """
        top_sites = get_top_websites(num)
        result = []
        if top_sites:
            for ip, site_info in top_sites.items():
                name = site_info["domain"].strip()
                if not name or name in ["unknown", "error"]:
                    name = ip + " (unknown)"
                if name == "error":
                    print("Error in site name")
                    continue
                result.append(Site(
                    name=name,
                    duration=site_info["total_duration"],
                    total_bytes=site_info["total_bytes"],
                    total_packets=0,  # TODO
                    visits=site_info["total_connections"]
                ))

            if len(result) >= num:
                return result

        # if no data, return pihole data
        top_sites = dns_get_top_websites(num - len(result))
        print("Top Sites:", top_sites)
        if not top_sites:
            return result

        for site, visits in top_sites.items():
            if site == "error":
                print("Error in site name")
                site = "wazuh.local"

            result.append(Site(
                name=site,
                duration=0,
                total_bytes=0,
                total_packets=0,
                visits=visits
            ))

        return result

