import csv
import eel 
from xml2csvoutput import process
from reqfunc import cvereq
cvelist = []
portlist = []
urllist = []
def csvread(device):
    process('script.txt')
    with open('output.csv', 'r') as csv_file:
        csv_reader = csv.reader(csv_file)
        # Port = [1] id = [2] severity = [3] url = [4]
        next(csv_reader)
        for row in csv_reader:
            if row[0] == device:
             cve = row[2]
             port = row[1]
             
             severity = row[3]
             url = row[4]

             cvelist.append(cve)
             portlist.append(port)
             urllist.append(url)

            
    
        csv_file.close()
    eel.Scanresult(cvelist, portlist, urllist)
    print('Loading vulnerability info..')
    cvereq(cvelist, urllist)
    print('Vulnerability info loaded')
    
