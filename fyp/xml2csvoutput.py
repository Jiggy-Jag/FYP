from xml.etree import ElementTree
import csv
from os import path


CSV_HEADERS = ['host', 'port',  'id_vuln', 'cvss',  'url']

def is_open(x):
    state = x.find("state")
    return state.attrib['state'] == "open"

def get_vulners(x):
    script = x.find("script[@id='vulners']")
    if script is None:
        return []
    else:
        t = script.find("table")
        vulns = []
        tables = t.findall('table')
        for t in tables:
            vuln = { 'id': t.find("elem[@key='id']").text,
                'cvss': t.find("elem[@key='cvss']").text,
                'type': t.find("elem[@key='type']").text,
            }
            vuln['url'] = f"https://www.vulners.com/{vuln['type']}/{vuln['id']}" 
            vulns.append(vuln)
        return vulns


def final_get(host):
    ports = host.findall('ports//port')
    open_ports = [p for p in ports if is_open(p)]
    FinalRes = []
    
    for x in open_ports:
        vulners = get_vulners(x)
        for v in vulners:
            Res = {
                'host': host.find("address").attrib['addr'],
                'port': x.attrib['portid'],
                'id_vuln':  v['id'],
                'cvss' : v['cvss'],
                'url':  v['url'],
            }
            FinalRes.append(Res)
    return FinalRes




def process(XML_File, output = 'output.csv'):
    document = ElementTree.parse(XML_File)
    hosts = document.findall('host')
    Reslist = []
    for host in hosts:
        Reslist.extend(final_get(host))
    with open(path.join(output),  'w', encoding='utf-8', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=CSV_HEADERS)
        writer.writeheader()
        writer.writerows(Reslist)
    pass