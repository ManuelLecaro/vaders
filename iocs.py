import requests, base64
from requests.auth import HTTPBasicAuth
import re
import json
import time

def isIp(input_string):
    regex = re.compile('[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', re.I)
    match = regex.match(str(input_string))
    return bool(match)

def isHost(input_string):
    regex = re.compile('([a-zA-Z]|\d)+\.?([a-zA-Z]|\d)+\.+[a-zA-Z]+', re.I)
    match = regex.search(str(input_string))
    return bool(match)

ips=[]
hosts=[]
hashes=[]

fileDa=open("reto.csv","r")
fileDa.readline()
fileDa.readline()
for line in fileDa.readlines():
    if(line.find("\n")!=0):
        line = line.replace("\n","")
        line = line.replace("[","")
        line = line.replace("]","")
        if isIp(line):
            ips.append(line)
        elif isHost(line):
            hosts.append(line)
        else:
            hashes.append(line)


print("Detalle:")
print("URLs")

cntBuenaRep = 0
cnt=0
for mystr in hosts:
    host=requests.get('https://api.fraudguard.io/v2/hostname/'+mystr, verify=True, auth=HTTPBasicAuth('OMlpmoiH1ehiqzf3', 'vM3h5ah0PI6W5CMk'))
    print(str(cnt)+". "+mystr)
    #print (host.text)
    dictHost=json.loads(host.text)
    print("Geolocalizacion: "+dictHost["state"]+" - "+ dictHost["country"])
    print("Reputacion/Categoria: "+ dictHost["threat"] + " / " + dictHost["risk_level"])
    if(int(dictHost["risk_level"])!=0):
        cntBuenaRep = cntBuenaRep + 1
    cnt=cnt+1


print("IPs")
cntMaliciosa=0
cnt=0
for mystr in ips:
    ip=requests.get('https://api.fraudguard.io/v2/ip/'+mystr, verify=True, auth=HTTPBasicAuth('OMlpmoiH1ehiqzf3', 'vM3h5ah0PI6W5CMk'))
    print(str(cnt)+". "+mystr)
    #print (ip.text)
    
    dictIp=json.loads(ip.text)
    print("Geolocalizacion: "+dictIp["state"]+" - "+ dictIp["country"])
    print("Reputacion/Categoria: "+ dictIp["threat"] + " / " + dictIp["risk_level"])
    if(int(dictIp["risk_level"])!=0):
        cntMaliciosa = cntMaliciosa + 1
    cnt=cnt+1

print("Hashes")
apiKey='0a4804f73b6593584da6239c48ada42c3747c90859844b7c136f472d37545842'
cnt=0
cntNoDetectado=0
for mystr in hashes:
    if cnt!=0 and cnt%4==0:
        time.sleep(61)
    ip=requests.get('https://www.virustotal.com/vtapi/v2/file/report?apikey='+apiKey+'&resource='+mystr)
    #print(ip.text)
    print(str(cnt)+". "+mystr)
    dictHash=json.loads(ip.text)
    flag=0
    for name , detail in dictHash["scans"].items():
        if(detail["detected"]):
            print(name + "? Si")
            flag=1
        else:
            print(name + "? No")
    if not flag:
        cntNoDetectado=cntNoDetectado+1
    cnt=cnt+1

print("Resumen")
print("Cantidad de URLs: "+ str(len(hosts)))
print("\tNo Maliciosas"+str(len(hosts)-cntMaliciosa))

print("Cantidad de IPs: "+ str(len(ips)))
print("\tReputacion Buena:"+str(cntBuenaRep))


print("Cantidad de Hashes: "+ str(len(hashes)))
print("\tNo detectada por ninguno de los antivirus"+str(cntNoDetectado))

#ip=requests.get('https://www.virustotal.com/vtapi/v2/file/report?apikey='+apiKey+'&resource='+'3d16542d4ee5c8f77e6c0281d283c7bc')
#print (ip.text)

#ip=requests.get('https://api.fraudguard.io/v2/ip/', verify=True, auth=HTTPBasicAuth('OMlpmoiH1ehiqzf3', 'vM3h5ah0PI6W5CMk'))
#print (ip.text)