import nmap
import json
import eel
import socket
from exce import csvread

@eel.expose
def networkscan(userinput):
    print('Scanning network, Please wait while the scan is in progress')
    devicesname = []
    devicesip = []
    tcplist = []
    nm = nmap.PortScanner()
    scan = nm.scan(hosts=userinput + '/24',  arguments='-F')
    result1 = json.dumps(scan, indent=2)
    data = json.loads(result1)
    hostlist = [(x, nm[x]['status']['state'],socket.gethostbyaddr(x)[0])
    for x in nm.all_hosts() if socket.gethostbyaddr(x)[0]]
    for host, status,name in hostlist: 
        devicesname.append(name)
        devicesip.append(host) 
        eel.thegreatone(name, host, data)

        

@eel.expose        
def devicescan(userinput, portnumber):
    print('Scanning device, Please wait while the scan is in progress')
    nm = nmap.PortScanner()
    if portnumber in ['all']:
        scan = nm.scan(hosts= userinput, arguments="-sV --script vulners" )
        tt = nm.get_nmap_last_output()
        with open('script.txt', 'w') as f:
            f.truncate()
            f.write(tt)
            f.close()
        csvread(userinput)
    else:
        scan = nm.scan(userinput, portnumber, arguments="-sV --script vulners")
        tt = nm.get_nmap_last_output()
        with open('script.txt', 'w') as f:
            f.truncate()
            f.write(tt)
            f.close()
        csvread(userinput)
    
    print('Network scanned.')

    