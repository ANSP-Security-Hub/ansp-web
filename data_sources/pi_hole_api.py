#!../venv/bin/python
from APiHole import PiHole

from dotenv import load_dotenv
import os

load_dotenv()


class PiHoleApi:
    def __init__(self, pihole_ip='127.0.0.1'):
        self.IP = pihole_ip
        self.API_KEY = os.getenv('PIHOLE_API_KEY')

    def block_domain(self, domain) -> bool:
        return PiHole.AddBlock(self.IP, self.API_KEY, domain)

    def allow_domain(self, domain) -> bool:
        return PiHole.RemoveBlock(self.IP, self.API_KEY, domain)

    def top_items(self, number):
        Items = PiHole.GetTopItems(self.IP, self.API_KEY, number)
        ItemsTop = Items['top_queries']
        resultListTOP = list(ItemsTop.items())
        rtnTOP = []
        ItemsADS = Items['top_ads']
        resultListADS = list(ItemsADS.items())
        rtnADS = []
        for l in range(len(resultListTOP)):
            rtnTOP.append(str(resultListTOP[l][0]) + ' : ' + str(resultListTOP[l][1]))
        for n in range(len(resultListADS)):
            rtnADS.append(str(resultListADS[n][0] + ' : ' + str(resultListADS[n][1])))

        return str(rtnTOP), str(rtnADS)


if __name__ == '__main__':
    pi = PiHoleApi()

    print("remove from blocked domains")
    pi.allow_domain('facebook.com')

    print("Get the 15 top Items")
    pp = pi.top_items(15)
    print(f"Top queries:\n{pp[0]}")
    print(f"Top Ads:\n{pp[1]}")
