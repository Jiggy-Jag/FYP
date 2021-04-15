import requests
from bs4 import BeautifulSoup
import re
import eel
import json
import vulners


def cvereq (cvelist, url):
    vulners_api = vulners.Vulners(api_key="6HB4GW9IJBZ2AJZGEDQ60O61SJAYWX1B3YH2DYOY28FXY1XKHT416WT1N3TFJFO7")
    for cve in cvelist:
        tes = vulners_api.document(cve)
        Title = tes.get("title")
        Description = tes.get("description")
        eel.Results(Title, Description, cve, url)